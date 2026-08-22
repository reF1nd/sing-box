package trafficcontrol

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/interrupt"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

func TestSelectedPacketConnPreservesDomain(t *testing.T) {
	for _, wrapping := range []string{"tracked", "interrupt-tracked", "tracked-interrupt"} {
		t.Run(wrapping, func(t *testing.T) {
			group := &selectionTestOutbound{tag: "group"}
			leaf := &selectionTestOutbound{tag: "leaf"}
			upstream := &selectionTestPacketConn{destination: M.ParseSocksaddr("example.com:53")}
			var conn net.PacketConn = upstream
			if wrapping == "tracked-interrupt" {
				conn = interrupt.NewGroup().NewPacketConn(conn, false, false)
			}
			conn = TrackOutboundPacketConn(conn, group, leaf)
			if wrapping == "interrupt-tracked" {
				conn = interrupt.NewGroup().NewPacketConn(conn, false, false)
			}
			t.Cleanup(func() { require.NoError(t, conn.Close()) })
			require.Implements(t, (*N.NetPacketConn)(nil), conn)
			packetConn := bufio.NewPacketConn(conn)
			buffer := buf.NewPacket()
			defer buffer.Release()
			reader, _ := N.UnwrapCountPacketReader(packetConn, nil)
			writer, _ := N.UnwrapCountPacketWriter(packetConn, nil)
			destination, err := reader.ReadPacket(buffer)
			require.NoError(t, err)
			require.Equal(t, upstream.destination, destination)
			require.Equal(t, "response", string(buffer.Bytes()))
			require.NoError(t, writer.WritePacket(buf.As([]byte("request")), destination))
			require.Equal(t, destination, upstream.writtenDestination)
			require.Equal(t, "request", upstream.writtenPayload)

			upstream.err = errors.New("packet failure")
			_, err = packetConn.ReadPacket(buffer)
			require.ErrorIs(t, err, upstream.err)
			require.ErrorIs(t, writer.WritePacket(buf.As([]byte("request")), destination), upstream.err)
		})
	}
}

func TestSelectedPacketConnUDPFallback(t *testing.T) {
	local, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	group := &selectionTestOutbound{tag: "group"}
	leaf := &selectionTestOutbound{tag: "leaf"}
	tracked := TrackOutboundPacketConn(local, group, leaf)
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

type selectionTestPacketConn struct {
	net.PacketConn
	destination        M.Socksaddr
	writtenDestination M.Socksaddr
	writtenPayload     string
	err                error
}

func (c *selectionTestPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	if c.err != nil {
		return M.Socksaddr{}, c.err
	}
	_, err := buffer.Write([]byte("response"))
	return c.destination, err
}

func (c *selectionTestPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	defer buffer.Release()
	c.writtenDestination = destination
	c.writtenPayload = string(buffer.Bytes())
	return c.err
}

func (c *selectionTestPacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	return 0, nil, errors.New("unexpected ReadFrom")
}

func (c *selectionTestPacketConn) WriteTo([]byte, net.Addr) (int, error) {
	return 0, errors.New("unexpected WriteTo")
}

func (c *selectionTestPacketConn) Close() error {
	return nil
}

type selectionTestOutbound struct {
	adapter.Outbound
	tag string
}

func (o *selectionTestOutbound) Tag() string  { return o.tag }
func (o *selectionTestOutbound) Type() string { return "direct" }
