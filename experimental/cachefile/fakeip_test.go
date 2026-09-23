package cachefile

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFakeIPResetWithMissingBuckets(t *testing.T) {
	t.Parallel()

	cache := newDNSCacheTestCache(t)
	require.NoError(t, cache.FakeIPReset())

	address := netip.MustParseAddr("198.18.0.2")
	require.NoError(t, cache.FakeIPStore(address, "a.example.com"))
	require.NoError(t, cache.FakeIPReset())
	_, loaded := cache.FakeIPLoad(address)
	require.False(t, loaded)
	_, loaded = cache.FakeIPLoadDomain("a.example.com", false)
	require.False(t, loaded)
}
