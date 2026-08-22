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
	"github.com/sagernet/sing-box/log"

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
	scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
	t.Cleanup(func() { require.NoError(t, scope.Close()) })
	require.NoError(t, scope.Start("traffic", manager.traffic, adapter.StartStateInitialize))
	require.NoError(t, scope.Start("observability", manager, adapter.StartStateInitialize))
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

func TestRecentConnectionsSurviveGC(t *testing.T) {
	manager := newTestManager(t, true)
	manager.recentTTL = time.Hour
	scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
	t.Cleanup(func() { require.NoError(t, scope.Close()) })
	require.NoError(t, scope.Start("traffic", manager.traffic, adapter.StartStateInitialize))
	require.NoError(t, scope.Start("observability", manager, adapter.StartStateInitialize))
	outbound := &snapshotOutbound{tag: "direct", kind: "direct"}
	flow := manager.traffic.RoutedFlow(context.Background(), adapter.InboundContext{
		Network: "udp", OutboundChain: []adapter.Outbound{outbound},
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
