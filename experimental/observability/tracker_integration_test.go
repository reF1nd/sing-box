package observability

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/trafficcontrol"

	"github.com/stretchr/testify/require"
)

type snapshotOutbound struct {
	adapter.Outbound
	tag string
}

func (o *snapshotOutbound) Tag() string  { return o.tag }
func (o *snapshotOutbound) Type() string { return "direct" }

type snapshotOutboundManager struct {
	adapter.OutboundManager
	leaf adapter.Outbound
}

func (m *snapshotOutboundManager) Outbound(tag string) (adapter.Outbound, bool) {
	return m.leaf, tag == m.leaf.Tag()
}

func TestFlowTrafficAttribution(t *testing.T) {
	manager := newTestManager(t, true)
	leaf := &snapshotOutbound{tag: "first"}
	manager.traffic = trafficcontrol.NewManager(&snapshotOutboundManager{leaf: leaf})
	require.NoError(t, manager.traffic.Start(adapter.StartStateInitialize))
	t.Cleanup(func() { require.NoError(t, manager.traffic.Close()) })
	require.NoError(t, manager.Start(adapter.StartStateInitialize))
	t.Cleanup(func() { require.NoError(t, manager.Close()) })
	// The flow pre-match path already supplies its final outbound.
	flow := manager.traffic.RoutedFlow(context.Background(), adapter.InboundContext{Network: "udp"}, nil, leaf)
	flow.AttachFlow(nil)
	flow.CountForward(123)
	flow.CountReverse(456)
	active := manager.traffic.Connections()
	require.Len(t, active, 1)
	require.Equal(t, "first", manager.connectionFromMetadata(*active[0]).Outbound)
	flow.CloseFlow(0)
	flow.CloseFlow(0)
	require.True(t, active[0].ClosedAt.IsZero(), "closing must not mutate published active/event snapshots")
	response := httptest.NewRecorder()
	manager.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	require.Equal(t, http.StatusOK, response.Code)
	require.Contains(t, response.Body.String(), `singbox_outbound_upload_bytes_total{outbound="first"} 123`)
	require.Contains(t, response.Body.String(), `singbox_outbound_download_bytes_total{outbound="first"} 456`)
	require.Contains(t, response.Body.String(), `singbox_outbound_connections_active{outbound="first"} 0`)
	require.Contains(t, response.Body.String(), `singbox_outbound_connections_total{outbound="first"} 1`)
	require.Len(t, manager.traffic.ClosedConnections(), 1)
}
