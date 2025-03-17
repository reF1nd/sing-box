package route

import (
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/expiringmap"
	C "github.com/sagernet/sing-box/constant"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/stretchr/testify/require"
)

func TestRouterQUICSniffCacheRefreshAndExpiry(t *testing.T) {
	router := &Router{quicSniffCache: expiringmap.New[quicSniffCacheKey, string](200 * time.Millisecond)}
	t.Cleanup(router.quicSniffCache.Close)
	source := M.ParseSocksaddr("127.0.0.1:10000")
	destination := M.ParseSocksaddr("1.1.1.1:443")
	router.cacheQUICSniff(source, destination, "old.example")
	time.Sleep(120 * time.Millisecond)
	router.cacheQUICSniff(source, destination, "new.example")
	time.Sleep(120 * time.Millisecond)
	host, loaded := router.lookupQUICSniff(source, destination)
	require.True(t, loaded)
	require.Equal(t, "new.example", host)
	require.Eventually(t, func() bool {
		return router.quicSniffCache.Len() == 0
	}, 2*time.Second, 10*time.Millisecond)
}

func TestRouterQUICSniffCacheLookupRefreshesTTL(t *testing.T) {
	router := &Router{quicSniffCache: expiringmap.New[quicSniffCacheKey, string](200 * time.Millisecond)}
	t.Cleanup(router.quicSniffCache.Close)
	source := M.ParseSocksaddr("127.0.0.1:10000")
	destination := M.ParseSocksaddr("1.1.1.1:443")
	router.cacheQUICSniff(source, destination, "example.com")
	time.Sleep(120 * time.Millisecond)
	host, loaded := router.lookupQUICSniff(source, destination)
	require.True(t, loaded)
	require.Equal(t, "example.com", host)
	time.Sleep(120 * time.Millisecond)
	host, loaded = router.lookupQUICSniff(source, destination)
	require.True(t, loaded)
	require.Equal(t, "example.com", host)
	require.Eventually(t, func() bool {
		return router.quicSniffCache.Len() == 0
	}, 2*time.Second, 10*time.Millisecond)
}

func TestRouterQUICSniffCacheRefreshesOnCloseAfterOriginalExpiry(t *testing.T) {
	router := &Router{quicSniffCache: expiringmap.New[quicSniffCacheKey, string](20 * time.Millisecond)}
	t.Cleanup(router.quicSniffCache.Close)
	source := M.ParseSocksaddr("127.0.0.1:10000")
	destination := M.ParseSocksaddr("1.1.1.1:443")
	router.cacheQUICSniff(source, destination, "example.com")
	require.Eventually(t, func() bool {
		return router.quicSniffCache.Len() == 0
	}, time.Second, 10*time.Millisecond)
	closed := false
	onClose := router.wrapQUICSniffIdleCache(adapter.InboundContext{
		Protocol:    C.ProtocolQUIC,
		Source:      source,
		Destination: destination,
		SniffHost:   "example.com",
	}, func(error) {
		closed = true
	})
	onClose(nil)
	require.True(t, closed)
	host, loaded := router.lookupQUICSniff(source, destination)
	require.True(t, loaded)
	require.Equal(t, "example.com", host)
}

func TestRouterQUICSniffCacheCloseKeepsNewerHost(t *testing.T) {
	router := &Router{quicSniffCache: expiringmap.New[quicSniffCacheKey, string](time.Second)}
	t.Cleanup(router.quicSniffCache.Close)
	source := M.ParseSocksaddr("127.0.0.1:10000")
	destination := M.ParseSocksaddr("1.1.1.1:443")
	router.cacheQUICSniff(source, destination, "new.example")
	onClose := router.wrapQUICSniffIdleCache(adapter.InboundContext{
		Protocol:    C.ProtocolQUIC,
		Source:      source,
		Destination: destination,
		SniffHost:   "old.example",
	}, func(error) {})
	onClose(nil)
	host, loaded := router.lookupQUICSniff(source, destination)
	require.True(t, loaded)
	require.Equal(t, "new.example", host)
}

func TestRouterQUICSniffCacheCloseUsesOriginalDestinationAfterOverride(t *testing.T) {
	router := &Router{quicSniffCache: expiringmap.New[quicSniffCacheKey, string](time.Second)}
	t.Cleanup(router.quicSniffCache.Close)
	source := M.ParseSocksaddr("127.0.0.1:10000")
	originDestination := M.ParseSocksaddr("1.1.1.1:443")
	onClose := router.wrapQUICSniffIdleCache(adapter.InboundContext{
		Protocol:          C.ProtocolQUIC,
		Source:            source,
		Destination:       M.ParseSocksaddr("example.com:443"),
		OriginDestination: originDestination,
		DestOverride:      true,
		SniffHost:         "example.com",
	}, func(error) {})
	onClose(nil)
	host, loaded := router.lookupQUICSniff(source, originDestination)
	require.True(t, loaded)
	require.Equal(t, "example.com", host)
}
