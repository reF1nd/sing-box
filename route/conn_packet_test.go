package route

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/interrupt"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

func TestTrackedPacketConnPreservesDomain(t *testing.T) {
	for _, wrapping := range []string{"tracked", "interrupt-tracked", "tracked-interrupt"} {
		t.Run(wrapping, func(t *testing.T) {
			manager := NewConnectionManager(nil)
			upstream := &trackedTestPacketConn{destination: M.ParseSocksaddr("example.com:53")}
			var conn net.PacketConn = upstream
			if wrapping == "tracked-interrupt" {
				conn = interrupt.NewGroup().NewPacketConn(conn, false, false)
			}
			conn = manager.TrackPacketConn(conn)
			if wrapping == "interrupt-tracked" {
				conn = interrupt.NewGroup().NewPacketConn(conn, false, false)
			}
			t.Cleanup(func() { require.NoError(t, conn.Close()) })
			require.Implements(t, (*N.NetPacketConn)(nil), conn)
			packetConn := bufio.NewPacketConn(conn)
			buffer := buf.NewPacket()
			defer buffer.Release()
			destination, err := packetConn.ReadPacket(buffer)
			require.NoError(t, err)
			require.Equal(t, upstream.destination, destination)
			require.Equal(t, "response", string(buffer.Bytes()))
			require.NoError(t, packetConn.WritePacket(buf.As([]byte("request")), destination))
			require.Equal(t, destination, upstream.writtenDestination)
			require.Equal(t, "request", upstream.writtenPayload)

			upstream.err = errors.New("packet failure")
			_, err = packetConn.ReadPacket(buffer)
			require.ErrorIs(t, err, upstream.err)
			require.ErrorIs(t, packetConn.WritePacket(buf.As([]byte("request")), destination), upstream.err)
		})
	}
}

func TestTrackedPacketConnUDPFallback(t *testing.T) {
	local, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	manager := NewConnectionManager(nil)
	tracked := manager.TrackPacketConn(local)
	t.Cleanup(func() { tracked.Close() })
	require.Implements(t, (*N.NetPacketConn)(nil), tracked)
	conn := bufio.NewPacketConn(tracked)
	peer, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer peer.Close()
	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
	require.NoError(t, peer.SetDeadline(time.Now().Add(5*time.Second)))
	_, err = peer.WriteTo([]byte("response"), conn.LocalAddr())
	require.NoError(t, err)
	buffer := buf.NewPacket()
	defer buffer.Release()
	source, err := conn.ReadPacket(buffer)
	require.NoError(t, err)
	require.Equal(t, M.SocksaddrFromNet(peer.LocalAddr()).Unwrap(), source)
	require.Equal(t, "response", string(buffer.Bytes()))
	require.NoError(t, conn.WritePacket(buf.As([]byte("request")), source))
	response := make([]byte, 64)
	n, address, err := peer.ReadFrom(response)
	require.NoError(t, err)
	require.Equal(t, "request", string(response[:n]))
	require.Equal(t, conn.LocalAddr(), address)

	require.NoError(t, local.Close())
	_, err = conn.ReadPacket(buffer)
	require.ErrorIs(t, err, net.ErrClosed)
	require.ErrorIs(t, conn.WritePacket(buf.As([]byte("request")), source), net.ErrClosed)
}

type trackedTestPacketConn struct {
	net.PacketConn
	destination        M.Socksaddr
	writtenDestination M.Socksaddr
	writtenPayload     string
	err                error
}

func (c *trackedTestPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	if c.err != nil {
		return M.Socksaddr{}, c.err
	}
	_, err := buffer.Write([]byte("response"))
	return c.destination, err
}

func (c *trackedTestPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	defer buffer.Release()
	c.writtenDestination = destination
	c.writtenPayload = string(buffer.Bytes())
	return c.err
}

func (c *trackedTestPacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	return 0, nil, errors.New("unexpected ReadFrom")
}

func (c *trackedTestPacketConn) WriteTo([]byte, net.Addr) (int, error) {
	return 0, errors.New("unexpected WriteTo")
}

func (c *trackedTestPacketConn) Close() error {
	return nil
}
