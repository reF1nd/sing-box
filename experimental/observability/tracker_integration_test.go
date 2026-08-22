package observability

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/trafficcontrol"
	"github.com/sagernet/sing-box/log"

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
	scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
	t.Cleanup(func() { require.NoError(t, scope.Close()) })
	require.NoError(t, scope.Start("traffic", manager.traffic, adapter.StartStateInitialize))
	require.NoError(t, scope.Start("observability", manager, adapter.StartStateInitialize))
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

func TestRecentConnectionsSurviveGC(t *testing.T) {
	manager := newTestManager(t, true)
	outbound := &snapshotOutbound{tag: "direct"}
	manager.traffic = trafficcontrol.NewManager(&snapshotOutboundManager{leaf: outbound})
	manager.recentTTL = time.Hour
	scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
	t.Cleanup(func() { require.NoError(t, scope.Close()) })
	require.NoError(t, scope.Start("traffic", manager.traffic, adapter.StartStateInitialize))
	require.NoError(t, scope.Start("observability", manager, adapter.StartStateInitialize))
	flow := manager.traffic.RoutedFlow(context.Background(), adapter.InboundContext{
		Network: "udp",
	}, nil, outbound)
	flow.AttachFlow(nil)
	flow.CountForward(123)
	flow.CountReverse(456)
	flow.CloseFlow(0)
	require.Len(t, manager.traffic.ClosedConnections(), 1)

	for range 3 {
		runtime.GC()
		// Cleanup runs asynchronously after GC; keep observing the real registered callback.
		require.Never(t, func() bool { return len(manager.traffic.ClosedConnections()) != 1 }, 100*time.Millisecond, time.Millisecond)
	}
	response := httptest.NewRecorder()
	manager.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/connections/recent?window=1h", nil))
	require.Equal(t, http.StatusOK, response.Code)
	var page ConnectionPage
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &page))
	require.Equal(t, 1, page.Total)
	require.Len(t, page.Data, 1)
	require.Equal(t, int64(123), page.Data[0].Upload)
	require.Equal(t, int64(456), page.Data[0].Download)
	top, err := manager.topDimensions("network", time.Hour, 100)
	require.NoError(t, err)
	require.Equal(t, 1, top.Total)
	require.Equal(t, int64(1), top.Data[0].Connections)
	upload, download := manager.traffic.Total()
	require.Equal(t, int64(123), upload)
	require.Equal(t, int64(456), download)
}
