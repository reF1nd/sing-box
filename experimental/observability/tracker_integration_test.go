package observability

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sagernet/sing-box/adapter"

	"github.com/stretchr/testify/require"
)

type snapshotOutbound struct {
	adapter.Outbound
	tag  string
	kind string
}

func (o *snapshotOutbound) Tag() string  { return o.tag }
func (o *snapshotOutbound) Type() string { return o.kind }

func TestResolvedChainTrafficAttribution(t *testing.T) {
	manager := newTestManager(t, true)
	require.NoError(t, manager.traffic.Start(adapter.StartStateInitialize))
	t.Cleanup(func() { require.NoError(t, manager.traffic.Close()) })
	require.NoError(t, manager.Start(adapter.StartStateInitialize))
	t.Cleanup(func() { require.NoError(t, manager.Close()) })
	outer := &snapshotOutbound{tag: "select", kind: "selector"}
	balance := &snapshotOutbound{tag: "balance", kind: "loadbalance"}
	leaf := &snapshotOutbound{tag: "first", kind: "direct"}
	chain := []adapter.Outbound{outer, balance, leaf}
	metadata := adapter.InboundContext{Network: "udp", OutboundChain: chain}
	flow := manager.traffic.RoutedFlow(context.Background(), metadata, nil, outer)
	flow.AttachFlow(nil)
	// Later selections must not change the attribution captured at routing time.
	chain[2] = &snapshotOutbound{tag: "second", kind: "direct"}
	flow.CountForward(123)
	flow.CountReverse(456)
	active := manager.traffic.Connections()
	require.Len(t, active, 1)
	connection := manager.connectionFromMetadata(*active[0])
	require.Equal(t, []string{"first", "balance", "select"}, connection.Chain)
	require.Equal(t, "first", connection.Outbound)
	flow.CloseFlow(0)
	flow.CloseFlow(0)
	response := httptest.NewRecorder()
	manager.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	require.Equal(t, http.StatusOK, response.Code)
	require.Contains(t, response.Body.String(), `singbox_outbound_upload_bytes_total{outbound="first > balance > select"} 123`)
	require.Contains(t, response.Body.String(), `singbox_outbound_download_bytes_total{outbound="first > balance > select"} 456`)
	require.Contains(t, response.Body.String(), `singbox_outbound_connections_active{outbound="first > balance > select"} 0`)
	require.Contains(t, response.Body.String(), `singbox_outbound_connections_total{outbound="first > balance > select"} 1`)
	require.NotContains(t, response.Body.String(), `outbound="second`)
	require.Len(t, manager.traffic.ClosedConnections(), 1)
}
