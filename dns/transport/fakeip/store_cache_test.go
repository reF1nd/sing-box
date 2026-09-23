package fakeip_test

import (
	"context"
	"net/netip"
	"path/filepath"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/dns/transport/fakeip"
	"github.com/sagernet/sing-box/experimental/cachefile"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

func TestStoreResetPreservesReservationsAfterUncleanRestart(t *testing.T) {
	t.Parallel()

	for _, isIPv6 := range []bool{false, true} {
		name := "IPv4"
		if isIPv6 {
			name = "IPv6"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			path := filepath.Join(t.TempDir(), "cache.db")
			openStore := func() (*cachefile.CacheFile, *fakeip.Store, func()) {
				cache := cachefile.New(context.Background(), logger.NOP(), option.CacheFileOptions{
					Path:        path,
					StoreFakeIP: true,
				})
				require.NoError(t, cache.Start(adapter.StartStateInitialize))
				closed := false
				closeCache := func() {
					if !closed {
						closed = true
						require.NoError(t, cache.Close())
					}
				}
				t.Cleanup(closeCache)
				ctx := service.ContextWith[adapter.CacheFile](context.Background(), cache)
				store := fakeip.NewStore(ctx, logger.NOP(), netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("fc00::/18"))
				require.NoError(t, store.Start())
				return cache, store, closeCache
			}

			cache, store, closeCache := openStore()
			oldAddress, err := store.Create("before-reset.example", isIPv6)
			require.NoError(t, err)
			require.NoError(t, store.Reset())
			_, loaded := store.Lookup(oldAddress)
			require.False(t, loaded)

			beforeRestart, err := store.Create("after-reset.example", isIPv6)
			require.NoError(t, err)
			require.Equal(t, oldAddress, beforeRestart)
			cache.Flush()
			// Preserve persisted mappings without Store.Close updating metadata,
			// matching an unclean process exit after the cache has been flushed.
			closeCache()

			_, store, _ = openStore()
			domain, loaded := store.Lookup(beforeRestart)
			require.True(t, loaded)
			require.Equal(t, "after-reset.example", domain)
			afterRestart, err := store.Create("after-restart.example", isIPv6)
			require.NoError(t, err)
			require.NotEqual(t, beforeRestart, afterRestart, "a persisted mapping must not be reassigned to another domain")
			domain, loaded = store.Lookup(beforeRestart)
			require.True(t, loaded)
			require.Equal(t, "after-reset.example", domain)
		})
	}
}
