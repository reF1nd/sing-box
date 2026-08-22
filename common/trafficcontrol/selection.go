package trafficcontrol

import (
	"net"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/bufio"
	N "github.com/sagernet/sing/common/network"
)

// Selection is attached to the returned connection, not shared dial context:
// retries and parallel attempts must not overwrite the winning connection's path.
type outboundSelection interface {
	trackedOutbound() ([]string, string, string)
}

type selectedOutbound struct {
	chain []string
	tag   string
	kind  string
}

func (s selectedOutbound) trackedOutbound() ([]string, string, string) { return s.chain, s.tag, s.kind }

func selectionFor(conn any, group, selected adapter.Outbound) selectedOutbound {
	s := selectedOutbound{chain: []string{selected.Tag()}, tag: selected.Tag(), kind: selected.Type()}
	if _, isGroup := selected.(adapter.OutboundGroup); isGroup {
		if previous, loaded := common.Cast[outboundSelection](conn); loaded {
			s.chain, s.tag, s.kind = previous.trackedOutbound()
		}
	}
	s.chain = append(append([]string(nil), s.chain...), group.Tag())
	return s
}

// TrackOutboundConn retains the selection made by a successful group dial.
func TrackOutboundConn(conn net.Conn, group, selected adapter.Outbound) net.Conn {
	return &selectedConn{Conn: conn, selectedOutbound: selectionFor(conn, group, selected)}
}

type selectedConn struct {
	net.Conn
	selectedOutbound
}

func (c *selectedConn) Upstream() any           { return c.Conn }
func (c *selectedConn) ReaderReplaceable() bool { return true }
func (c *selectedConn) WriterReplaceable() bool { return true }

// TrackOutboundPacketConn is the packet equivalent of TrackOutboundConn.
func TrackOutboundPacketConn(conn net.PacketConn, group, selected adapter.Outbound) net.PacketConn {
	return &selectedPacketConn{NetPacketConn: bufio.NewNetPacketConn(bufio.NewPacketConn(conn)), selectedOutbound: selectionFor(conn, group, selected)}
}

type selectedPacketConn struct {
	N.NetPacketConn
	selectedOutbound
}

func (c *selectedPacketConn) Upstream() any           { return c.NetPacketConn }
func (c *selectedPacketConn) ReaderReplaceable() bool { return true }
func (c *selectedPacketConn) WriterReplaceable() bool { return true }

// Handler delegation bypasses group dialing. Add that hop when the delegated
// handler reports its successful dial to the incoming connection.
func TrackOutboundHandlerConn(conn net.Conn, group, selected adapter.Outbound) net.Conn {
	return &selectedHandlerConn{Conn: conn, group: group, selected: selected}
}

type selectedHandlerConn struct {
	net.Conn
	group    adapter.Outbound
	selected adapter.Outbound
}

func (c *selectedHandlerConn) Upstream() any           { return c.Conn }
func (c *selectedHandlerConn) ReaderReplaceable() bool { return true }
func (c *selectedHandlerConn) WriterReplaceable() bool { return true }
func (c *selectedHandlerConn) ConnHandshakeSuccess(remote net.Conn) error {
	return N.ReportConnHandshakeSuccess(c.Conn, TrackOutboundConn(remote, c.group, c.selected))
}

func TrackOutboundHandlerPacketConn(conn N.PacketConn, group, selected adapter.Outbound) N.PacketConn {
	return &selectedHandlerPacketConn{PacketConn: conn, group: group, selected: selected}
}

type selectedHandlerPacketConn struct {
	N.PacketConn
	group    adapter.Outbound
	selected adapter.Outbound
}

func (c *selectedHandlerPacketConn) Upstream() any           { return c.PacketConn }
func (c *selectedHandlerPacketConn) ReaderReplaceable() bool { return true }
func (c *selectedHandlerPacketConn) WriterReplaceable() bool { return true }
func (c *selectedHandlerPacketConn) PacketConnHandshakeSuccess(remote net.PacketConn) error {
	return N.ReportPacketConnHandshakeSuccess(c.PacketConn, TrackOutboundPacketConn(remote, c.group, c.selected))
}
