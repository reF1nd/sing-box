package group

import (
	"context"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/interrupt"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/route"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

func TestSelectorInterruptRoutedConnections(t *testing.T) {
	for _, kind := range []string{"plain", "selector", "urltest", "loadbalance", "handler", "nested-handler"} {
		for _, network := range []string{N.NetworkTCP, N.NetworkUDP} {
			for _, policy := range []string{"interrupt", "keep", "resource-download"} {
				t.Run(kind+"/"+network+"/"+policy, func(t *testing.T) {
					ctx := context.Background()
					if policy == "resource-download" {
						ctx = interrupt.ContextWithIsResourceDownload(ctx)
					}
					logger := log.NewNOPFactory().NewLogger("test")
					manager := route.NewConnectionManager(logger)
					incoming := newSelectorInterruptTestConn()
					remote := newSelectorInterruptTestConn()
					t.Cleanup(func() { incoming.Close(); remote.Close() })
					leaf := &selectorInterruptTestOutbound{
						Adapter: outbound.NewAdapter("test", "leaf", []string{N.NetworkTCP, N.NetworkUDP}, nil),
						conn:    remote,
					}
					next := &selectorInterruptTestOutbound{}
					newSelector := func(selected adapter.Outbound) *Selector {
						s := &Selector{
							ctx: ctx, connection: manager, interruptGroup: interrupt.NewGroup(),
							interruptExternalConnections: policy != "keep",
							outbounds:                    map[string]adapter.Outbound{"next": next},
						}
						s.selected.Store(selected)
						return s
					}
					var selected adapter.Outbound = leaf
					var handler *selectorInterruptTestHandler
					switch kind {
					case "selector":
						selected = newSelector(leaf)
					case "urltest":
						group := &URLTestGroup{interruptGroup: interrupt.NewGroup()}
						group.selectedOutboundTCP.Store(leaf)
						group.selectedOutboundUDP.Store(leaf)
						selected = &URLTest{connection: manager, group: group}
					case "loadbalance":
						selected = &LoadBalance{connection: manager, group: &LoadBalanceGroup{
							interruptGroup: interrupt.NewGroup(),
							strategyFn:     func(*adapter.InboundContext, bool, outboundMatcher) adapter.Outbound { return leaf },
						}}
					case "handler", "nested-handler":
						handler = &selectorInterruptTestHandler{selectorInterruptTestOutbound: leaf}
						selected = handler
						if kind == "nested-handler" {
							selected = newSelector(handler)
						}
					}
					selector := newSelector(selected)
					metadata := adapter.InboundContext{Destination: M.Socksaddr{Fqdn: "example.com", Port: 443}}
					closed := make(chan struct{})
					onClose := func(error) { close(closed) }
					if network == N.NetworkTCP {
						selector.NewConnection(ctx, incoming, metadata, onClose)
					} else {
						// Hide the net.PacketConn methods to exercise the N.PacketConn adapter too.
						packetConn := struct{ N.PacketConn }{bufio.NewPacketConn(incoming)}
						selector.NewPacketConnection(ctx, packetConn, metadata, onClose)
					}
					if handler != nil {
						require.True(t, handler.called)
						require.Equal(t, metadata, handler.metadata)
						require.True(t, interrupt.IsExternalConnectionFromContext(handler.ctx))
						require.Equal(t, policy == "resource-download", interrupt.IsResourceDownloadFromContext(handler.ctx))
					} else {
						require.True(t, leaf.dialed)
					}
					require.True(t, selector.SelectOutbound("next"))
					if policy == "interrupt" {
						select {
						case <-incoming.closed:
						case <-time.After(time.Second):
							t.Fatal("switching the outer selector did not close the routed connection")
						}
					} else {
						select {
						case <-incoming.closed:
							t.Fatal("switching the outer selector closed a protected connection")
						case <-time.After(10 * time.Millisecond):
						}
					}
					// Complete normal teardown as well, including removal after interruption.
					if handler != nil {
						require.NoError(t, handler.close())
						handler.onClose(nil)
					} else {
						incoming.Close()
						remote.Close()
					}
					select {
					case <-closed:
					case <-time.After(time.Second):
						t.Fatal("connection teardown did not finish")
					}
				})
			}
		}
	}
}

type selectorInterruptTestOutbound struct {
	outbound.Adapter
	conn   *selectorInterruptTestConn
	dialed bool
}

func (o *selectorInterruptTestOutbound) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	o.dialed = true
	return o.conn, nil
}

func (o *selectorInterruptTestOutbound) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	o.dialed = true
	return o.conn, nil
}

// Like the DNS outbound, this outbound requires its handlers and cannot be dialed.
type selectorInterruptTestHandler struct {
	*selectorInterruptTestOutbound
	called   bool
	ctx      context.Context
	metadata adapter.InboundContext
	close    func() error
	onClose  N.CloseHandlerFunc
}

func (h *selectorInterruptTestHandler) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, os.ErrInvalid
}

func (h *selectorInterruptTestHandler) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, os.ErrInvalid
}

func (h *selectorInterruptTestHandler) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	h.called, h.ctx, h.metadata, h.close, h.onClose = true, ctx, metadata, conn.Close, onClose
}

func (h *selectorInterruptTestHandler) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	h.called, h.ctx, h.metadata, h.close, h.onClose = true, ctx, metadata, conn.Close, onClose
}

type selectorInterruptTestConn struct {
	closed chan struct{}
	once   sync.Once
}

func newSelectorInterruptTestConn() *selectorInterruptTestConn {
	return &selectorInterruptTestConn{closed: make(chan struct{})}
}

func (c *selectorInterruptTestConn) Close() error                { c.once.Do(func() { close(c.closed) }); return nil }
func (c *selectorInterruptTestConn) Read([]byte) (int, error)    { <-c.closed; return 0, net.ErrClosed }
func (c *selectorInterruptTestConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *selectorInterruptTestConn) ReadFrom([]byte) (int, net.Addr, error) {
	<-c.closed
	return 0, nil, net.ErrClosed
}
func (c *selectorInterruptTestConn) WriteTo(p []byte, _ net.Addr) (int, error) { return len(p), nil }
func (c *selectorInterruptTestConn) LocalAddr() net.Addr                       { return &net.UDPAddr{} }
func (c *selectorInterruptTestConn) RemoteAddr() net.Addr                      { return &net.TCPAddr{} }
func (c *selectorInterruptTestConn) SetDeadline(time.Time) error               { return nil }
func (c *selectorInterruptTestConn) SetReadDeadline(time.Time) error           { return nil }
func (c *selectorInterruptTestConn) SetWriteDeadline(time.Time) error          { return nil }
