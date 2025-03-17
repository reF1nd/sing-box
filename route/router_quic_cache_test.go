package route

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/expiringmap"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

func TestRouterQUICSniffCacheCloseWithoutParent(t *testing.T) {
	router := &Router{quicSniffCache: expiringmap.New[quicSniffCacheKey, string](time.Minute)}
	t.Cleanup(router.quicSniffCache.Close)
	metadata := quicCloseMetadata()
	onClose := router.wrapQUICSniffIdleCache(metadata, nil)
	require.NotNil(t, onClose)
	onClose(nil)
	host, loaded := router.lookupQUICSniff(metadata.Source, metadata.Destination)
	require.True(t, loaded)
	require.Equal(t, metadata.SniffHost, host)
}

func TestRouterQUICSniffCacheHandshakeResponseFailure(t *testing.T) {
	router := &Router{quicSniffCache: expiringmap.New[quicSniffCacheKey, string](time.Minute)}
	t.Cleanup(router.quicSniffCache.Close)
	metadata := quicCloseMetadata()
	handshakeErr := errors.New("write handshake response")
	conn := &quicClosePacketConn{handshakeErr: handshakeErr}
	remote := &quicCloseRemotePacketConn{}
	parentCalls := 0
	onClose := router.wrapQUICSniffIdleCache(metadata, func(err error) {
		parentCalls++
		require.ErrorIs(t, err, handshakeErr)
		require.Equal(t, 1, conn.closes)
		require.Equal(t, 1, remote.closes)
		host, loaded := router.lookupQUICSniff(metadata.Source, metadata.Destination)
		require.True(t, loaded)
		require.Equal(t, metadata.SniffHost, host)
	})
	manager := NewConnectionManager(logger.NOP())
	manager.NewPacketConnection(context.Background(), &quicCloseDialer{remote: remote}, conn, metadata, onClose)
	require.Equal(t, 1, parentCalls)
	require.Equal(t, 1, conn.closes)
	// A caller without any close callback must also be safe on this path.
	manager.NewPacketConnection(context.Background(), &quicCloseDialer{remote: &quicCloseRemotePacketConn{}}, &quicClosePacketConn{handshakeErr: handshakeErr}, metadata, nil)
}

func quicCloseMetadata() adapter.InboundContext {
	return adapter.InboundContext{
		Protocol:    C.ProtocolQUIC,
		Source:      M.ParseSocksaddr("127.0.0.1:10000"),
		Destination: M.ParseSocksaddr("1.1.1.1:443"),
		SniffHost:   "example.com",
	}
}

type quicClosePacketConn struct {
	N.PacketConn
	closes       int
	onClose      N.CloseHandlerFunc
	handshakeErr error
}

func (c *quicClosePacketConn) Close() error {
	c.closes++
	if c.onClose != nil {
		c.onClose(nil)
	}
	return nil
}

func (c *quicClosePacketConn) HandshakeSuccess() error {
	return c.handshakeErr
}

type quicCloseRemotePacketConn struct {
	net.PacketConn
	closes int
}

func (c *quicCloseRemotePacketConn) Close() error {
	c.closes++
	return nil
}

type quicCloseDialer struct {
	N.Dialer
	remote net.PacketConn
}

func (d *quicCloseDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return d.remote, nil
}

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
