package snell

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	snellprotocol "github.com/sagernet/sing-snell"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/stretchr/testify/require"
)

type quicProxyNATTestEvent struct {
	conn    N.PacketConn
	onClose N.CloseHandlerFunc
}

type quicProxyNATTestHandler struct {
	events chan quicProxyNATTestEvent
}

func (h *quicProxyNATTestHandler) NewPacketConnectionEx(_ context.Context, conn N.PacketConn, _ M.Socksaddr, _ M.Socksaddr, onClose N.CloseHandlerFunc) {
	h.events <- quicProxyNATTestEvent{conn: conn, onClose: onClose}
}

type quicProxyNATTestWriter struct{}

func (quicProxyNATTestWriter) WritePacket(buffer *buf.Buffer, _ M.Socksaddr) error {
	buffer.Release()
	return nil
}

type countingQUICProxyNATTestWriter struct {
	writes atomic.Int32
}

func (w *countingQUICProxyNATTestWriter) WritePacket(buffer *buf.Buffer, _ M.Socksaddr) error {
	w.writes.Add(1)
	buffer.Release()
	return nil
}

func newQUICProxyNATTestService(t *testing.T, timeout time.Duration, eventCount int) (*quicProxyNATService, *quicProxyNATTestHandler) {
	t.Helper()
	handler := &quicProxyNATTestHandler{events: make(chan quicProxyNATTestEvent, eventCount)}
	service := newQUICProxyNATService(handler, func(M.Socksaddr, M.Socksaddr, *snellprotocol.QUICProxySession) (context.Context, N.PacketWriter) {
		return context.Background(), quicProxyNATTestWriter{}
	}, timeout)
	t.Cleanup(service.Close)
	return service, handler
}

func TestQUICProxyNATHasNoCapacityEviction(t *testing.T) {
	const sessionCount = 1536
	service, handler := newQUICProxyNATTestService(t, time.Minute, sessionCount)
	target := M.ParseSocksaddr("example.com:443")
	for index := range sessionCount {
		source := M.ParseSocksaddrHostPort("127.0.0.1", uint16(index+1))
		session := snellprotocol.NewQUICProxySession([]byte("password"), target, nil)
		require.True(t, service.NewSession(source, session, []byte{0xc0, byte(index)}))
	}
	for range sessionCount {
		<-handler.events
	}
	require.Equal(t, sessionCount, service.Len())
}

func TestQUICProxyNATDelayedCloseKeepsReplacement(t *testing.T) {
	service, handler := newQUICProxyNATTestService(t, time.Minute, 2)
	source := M.ParseSocksaddr("127.0.0.1:10000")
	target := M.ParseSocksaddr("example.com:443")
	firstSession := snellprotocol.NewQUICProxySession([]byte("first-password"), target, nil)
	require.True(t, service.NewSession(source, firstSession, []byte{0xc0, 1}))
	firstEvent := <-handler.events

	service.access.Lock()
	firstEntry := service.entries[source.AddrPort()]
	service.removeLocked(firstEntry)
	service.access.Unlock()
	firstEntry.conn.closeInternal()

	secondSession := snellprotocol.NewQUICProxySession([]byte("second-password"), target, nil)
	require.True(t, service.NewSession(source, secondSession, []byte{0xc0, 2}))
	secondEvent := <-handler.events
	require.Len(t, secondEvent.conn.(*quicProxyNATConn).packetChan, 1)
	require.False(t, service.NewPacket(firstEntry, []byte{0xc0, 3}))
	require.Len(t, secondEvent.conn.(*quicProxyNATConn).packetChan, 1)
	firstEvent.onClose(net.ErrClosed)

	loadedEntry, loaded := service.Session(source)
	require.True(t, loaded)
	require.Same(t, secondSession, loadedEntry.session)
}

func TestQUICProxyNATExpiresWithoutTraffic(t *testing.T) {
	service, handler := newQUICProxyNATTestService(t, 20*time.Millisecond, 1)
	source := M.ParseSocksaddr("127.0.0.1:10000")
	session := snellprotocol.NewQUICProxySession([]byte("password"), M.ParseSocksaddr("example.com:443"), nil)
	require.True(t, service.NewSession(source, session, []byte{0xc0, 1}))
	<-handler.events
	require.Eventually(t, func() bool { return service.Len() == 0 }, time.Second, 10*time.Millisecond)
	_, loaded := service.Session(source)
	require.False(t, loaded)
}

func TestQUICProxyNATRejectsWriteAfterClose(t *testing.T) {
	writer := new(countingQUICProxyNATTestWriter)
	conn := &quicProxyNATConn{
		writer:     writer,
		packetChan: make(chan quicProxyNATPacket, 1),
		done:       make(chan struct{}),
	}
	conn.closeInternal()
	buffer := buf.NewSize(1)
	buffer.Extend(1)
	require.ErrorIs(t, conn.WritePacket(buffer, M.ParseSocksaddr("example.com:443")), net.ErrClosed)
	require.Zero(t, writer.writes.Load())
}
