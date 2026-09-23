package fakeip

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

func TestStoreResetClearsMemoryStorage(t *testing.T) {
	t.Parallel()

	store, err := NewStore(context.Background(), logger.NOP(), netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("fc00::/18"))
	require.NoError(t, err)
	require.NoError(t, store.Start())

	address4, err := store.Create("a.example.com", false)
	require.NoError(t, err)
	address6, err := store.Create("a.example.com", true)
	require.NoError(t, err)
	_, err = store.Create("b.example.com", false)
	require.NoError(t, err)

	require.NoError(t, store.Reset())

	_, loaded := store.Lookup(address4)
	require.False(t, loaded)
	_, loaded = store.Lookup(address6)
	require.False(t, loaded)

	newAddress4, err := store.Create("c.example.com", false)
	require.NoError(t, err)
	require.Equal(t, address4, newAddress4, "allocation restarts from the beginning of the range")
	newAddress6, err := store.Create("c.example.com", true)
	require.NoError(t, err)
	require.Equal(t, address6, newAddress6)
	domain, loaded := store.Lookup(newAddress4)
	require.True(t, loaded)
	require.Equal(t, "c.example.com", domain)
}

func TestStoreResetSingleStackAndSmallPoolWrap(t *testing.T) {
	t.Parallel()

	// Single-stack IPv4 small pool (/29: .1 reserved start, .2-.6 usable, .7 broadcast).
	store, err := NewStore(context.Background(), logger.NOP(), netip.MustParsePrefix("198.18.0.0/29"), netip.Prefix{})
	require.NoError(t, err)
	require.NoError(t, store.Start())

	first, err := store.Create("d1.example", false)
	require.NoError(t, err)
	require.Equal(t, netip.MustParseAddr("198.18.0.2"), first)
	for _, domain := range []string{"d2.example", "d3.example", "d4.example", "d5.example", "d6.example"} {
		_, err = store.Create(domain, false)
		require.NoError(t, err)
	}
	_, err = store.Create("v6.example", true)
	require.Error(t, err)

	require.NoError(t, store.Reset())
	afterReset, err := store.Create("fresh.example", false)
	require.NoError(t, err)
	require.Equal(t, first, afterReset)
	_, err = store.Create("v6.example", true)
	require.Error(t, err)
}

type failingResetCacheFile struct {
	adapter.CacheFile
	metadata *adapter.FakeIPMetadata
	resetErr error
}

func (f *failingResetCacheFile) StoreFakeIP() bool                   { return true }
func (f *failingResetCacheFile) FakeIPMetadata() *adapter.FakeIPMetadata { return f.metadata }
func (f *failingResetCacheFile) FakeIPReset() error                  { return f.resetErr }

func TestStoreStartPropagatesResetErrorOnPoolChange(t *testing.T) {
	t.Parallel()
	resetErr := errors.New("fakeip reset failed")
	cache := &failingResetCacheFile{
		metadata: &adapter.FakeIPMetadata{
			Inet4Range:   netip.MustParsePrefix("198.18.0.0/16"),
			Inet4Current: netip.MustParseAddr("198.18.0.2"),
		},
		resetErr: resetErr,
	}
	ctx := service.ContextWith[adapter.CacheFile](context.Background(), cache)
	store, err := NewStore(ctx, logger.NOP(), netip.MustParsePrefix("198.19.0.0/16"), netip.Prefix{})
	require.NoError(t, err)
	err = store.Start()
	require.ErrorIs(t, err, resetErr)
}
