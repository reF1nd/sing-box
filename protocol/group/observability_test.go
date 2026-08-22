package group

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/interrupt"
	"github.com/sagernet/sing-box/common/trafficcontrol"
	"github.com/sagernet/sing-box/experimental/observability"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/route"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// Exercise the real group's dial and handler paths. In particular URLTest.Now
// prefers TCP, which must not determine the attribution of a UDP connection.
func TestObservabilityGroupSelection(t *testing.T) {
	for _, network := range []string{N.NetworkTCP, N.NetworkUDP} {
		for _, handler := range []bool{false, true} {
			t.Run(network+map[bool]string{false: "/dial", true: "/handler"}[handler], func(t *testing.T) {
				ctx := context.Background()
				logger := log.NewNOPFactory().NewLogger("test")
				connectionManager := route.NewConnectionManager(logger)
				remote := newSelectorInterruptTestConn()
				t.Cleanup(func() { remote.Close() })
				leaf := &selectorInterruptTestOutbound{Adapter: outbound.NewAdapter("direct", "first", []string{network}, nil), conn: remote}
				other := &selectorInterruptTestOutbound{Adapter: outbound.NewAdapter("direct", "second", []string{network}, nil), conn: remote}
				urlGroup := &URLTestGroup{interruptGroup: interrupt.NewGroup()}
				urlGroup.selectedOutboundTCP.Store(other)
				urlGroup.selectedOutboundUDP.Store(other)
				if network == N.NetworkTCP {
					urlGroup.selectedOutboundTCP.Store(leaf)
				} else {
					urlGroup.selectedOutboundUDP.Store(leaf)
				}
				url := &URLTest{Adapter: outbound.NewAdapter("urltest", "url", []string{network}, nil), group: urlGroup, connection: connectionManager}
				balance := &LoadBalance{Adapter: outbound.NewAdapter("loadbalance", "balance", []string{network}, nil), connection: connectionManager, group: &LoadBalanceGroup{
					interruptGroup: interrupt.NewGroup(), strategyFn: func(*adapter.InboundContext, bool, outboundMatcher) adapter.Outbound { return url },
				}}
				selector := &Selector{Adapter: outbound.NewAdapter("selector", "select", []string{network}, nil), connection: connectionManager, interruptGroup: interrupt.NewGroup()}
				selector.selected.Store(balance)
				outboundManager := &loadBalanceURLTestOutboundManager{outbounds: map[string]adapter.Outbound{"select": selector, "balance": balance, "url": url, "first": leaf, "second": other}}
				traffic := trafficcontrol.NewManager(outboundManager)
				require.NoError(t, traffic.Start(adapter.StartStateInitialize))
				t.Cleanup(func() { require.NoError(t, traffic.Close()) })
				obs, err := observability.New(ctx, logger, traffic, option.ObservabilityOptions{})
				require.NoError(t, err)
				require.NoError(t, obs.Start(adapter.StartStateInitialize))
				t.Cleanup(func() { require.NoError(t, obs.Close()) })
				metadata := adapter.InboundContext{Network: network, Destination: M.Socksaddr{Fqdn: "example.com", Port: 443}}
				metadata.InitExtended()
				incoming := newSelectorInterruptTestConn()
				t.Cleanup(func() { incoming.Close() })
				closed := make(chan struct{})
				onClose := func(error) { close(closed) }
				var closeTracker func() error
				if network == N.NetworkTCP {
					tracked := traffic.RoutedConnection(ctx, incoming, metadata, nil, selector)
					closeTracker = tracked.Close
					if handler {
						selector.NewConnection(ctx, tracked, metadata, onClose)
					} else {
						dialed, dialErr := selector.DialContext(adapter.WithContext(ctx, &metadata), network, metadata.Destination)
						require.NoError(t, dialErr)
						selector.selected.Store(other)
						urlGroup.selectedOutboundTCP.Store(other)
						urlGroup.selectedOutboundUDP.Store(other)
						require.NoError(t, N.ReportConnHandshakeSuccess(tracked, dialed))
					}
					_, err = tracked.Write([]byte("payload"))
				} else {
					tracked := traffic.RoutedPacketConnection(ctx, bufio.NewPacketConn(incoming), metadata, nil, selector)
					closeTracker = tracked.Close
					if handler {
						selector.NewPacketConnection(ctx, tracked, metadata, onClose)
					} else {
						dialed, dialErr := selector.ListenPacket(adapter.WithContext(ctx, &metadata), metadata.Destination)
						require.NoError(t, dialErr)
						selector.selected.Store(other)
						urlGroup.selectedOutboundTCP.Store(other)
						urlGroup.selectedOutboundUDP.Store(other)
						require.NoError(t, N.ReportPacketConnHandshakeSuccess(tracked, dialed))
					}
					buffer := buf.As([]byte("payload"))
					err = tracked.WritePacket(buffer, metadata.Destination)
				}
				require.NoError(t, err)
				// Change every selection after the dial; active and closed snapshots must remain fixed.
				selector.selected.Store(other)
				urlGroup.selectedOutboundTCP.Store(other)
				urlGroup.selectedOutboundUDP.Store(other)
				active := traffic.Connections()
				require.Len(t, active, 1)
				require.Equal(t, []string{"first", "url", "balance", "select"}, active[0].Chain)
				require.Equal(t, "first", active[0].Outbound)
				require.Equal(t, "direct", active[0].OutboundType)
				require.NoError(t, closeTracker())
				require.NoError(t, closeTracker())
				if handler {
					select {
					case <-closed:
					case <-time.After(time.Second):
						t.Fatal("connection teardown did not finish")
					}
				}
				require.Zero(t, traffic.ConnectionsLen())
				require.Len(t, traffic.ClosedConnections(), 1)
				require.Equal(t, active[0].Chain, traffic.ClosedConnections()[0].Chain)
				response := httptest.NewRecorder()
				obs.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/metrics", nil))
				require.Contains(t, response.Body.String(), `singbox_outbound_download_bytes_total{outbound="first > url > balance > select"} 7`)
				require.Contains(t, response.Body.String(), `singbox_outbound_connections_total{outbound="first > url > balance > select"} 1`)
				require.Contains(t, response.Body.String(), `singbox_outbound_connections_active{outbound="first > url > balance > select"} 0`)
				require.NotContains(t, response.Body.String(), `outbound="second`)
			})
		}
	}
}

// A failed/no-handshake path still contributes its traffic and one closed connection.
func TestObservabilityWithoutHandshake(t *testing.T) {
	leaf := &selectorInterruptTestOutbound{Adapter: outbound.NewAdapter("direct", "leaf", nil, nil)}
	traffic := trafficcontrol.NewManager(&loadBalanceURLTestOutboundManager{outbounds: map[string]adapter.Outbound{"leaf": leaf}})
	require.NoError(t, traffic.Start(adapter.StartStateInitialize))
	defer traffic.Close()
	incoming := &observabilityReadConn{Conn: newSelectorInterruptTestConn(), Reader: strings.NewReader("payload")}
	tracked := traffic.RoutedConnection(context.Background(), incoming, adapter.InboundContext{}, nil, leaf)
	result, err := io.ReadAll(tracked)
	require.NoError(t, err)
	require.Equal(t, "payload", string(result))
	require.NoError(t, tracked.Close())
	require.NoError(t, tracked.Close())
	require.Len(t, traffic.ClosedConnections(), 1)
	require.Equal(t, int64(7), traffic.ClosedConnections()[0].Upload.Load())
}

type observabilityReadConn struct {
	net.Conn
	io.Reader
}

func (c *observabilityReadConn) Read(p []byte) (int, error) { return c.Reader.Read(p) }

func TestObservabilityCloseDuringDial(t *testing.T) {
	leaf := &selectorInterruptTestOutbound{Adapter: outbound.NewAdapter("direct", "leaf", nil, nil)}
	traffic := trafficcontrol.NewManager(&loadBalanceURLTestOutboundManager{outbounds: map[string]adapter.Outbound{"leaf": leaf}})
	require.NoError(t, traffic.Start(adapter.StartStateInitialize))
	defer traffic.Close()
	incoming := newSelectorInterruptTestConn()
	traffic.RoutedConnection(context.Background(), incoming, adapter.InboundContext{}, nil, leaf)
	traffic.CloseAllConnections()
	select {
	case <-incoming.closed:
	default:
		t.Fatal("pending dial was not closed")
	}
	require.Len(t, traffic.ClosedConnections(), 1)
	require.Zero(t, traffic.ConnectionsLen())
}
