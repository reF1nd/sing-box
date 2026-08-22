package observability

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/trafficcontrol"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

func TestPrometheusMetrics(t *testing.T) {
	manager := newTestManager(t, true)
	metadata := testMetadata()
	metadata.Chain = []string{"edge\\\"one", "proxy"}
	statistics := manager.TrafficCounters(metadata)
	statistics.UploadBytes.Add(123)
	statistics.DownloadBytes.Add(456)
	manager.ConnectionOpened(metadata)

	request := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	response := httptest.NewRecorder()
	manager.Handler().ServeHTTP(response, request)
	require.Equal(t, http.StatusOK, response.Code)
	require.Contains(t, response.Header().Get("Content-Type"), "text/plain")
	content := response.Body.String()
	require.Contains(t, content, "# TYPE singbox_connections_total counter")
	require.Contains(t, content, "singbox_connections_total 1")
	require.Contains(t, content, "singbox_outbound_upload_bytes_total{outbound=\"edge\\\\\\\"one > proxy\"} 123")
	require.Contains(t, content, "singbox_outbound_download_bytes_total{outbound=\"edge\\\\\\\"one > proxy\"} 456")

	manager.ConnectionClosed(metadata)
	response = httptest.NewRecorder()
	manager.Handler().ServeHTTP(response, request)
	require.Contains(t, response.Body.String(), "singbox_outbound_connections_active{outbound=\"edge\\\\\\\"one > proxy\"} 0")
}

func TestSensitiveConnectionFields(t *testing.T) {
	metadata := testMetadata()
	redacted := newTestManager(t, false).connectionFromMetadata(metadata)
	require.Empty(t, redacted.Domain)
	require.Empty(t, redacted.SourceIP)
	require.Empty(t, redacted.DestinationIP)
	require.Zero(t, redacted.SourcePort)
	require.Equal(t, uint16(443), redacted.DestinationPort)
	require.Empty(t, redacted.Rule)

	exposed := newTestManager(t, true).connectionFromMetadata(metadata)
	require.Equal(t, "example.com", exposed.Domain)
	require.Equal(t, "192.0.2.1", exposed.SourceIP)
	require.Equal(t, "198.51.100.2", exposed.DestinationIP)
	require.Equal(t, uint16(12345), exposed.SourcePort)
	require.Equal(t, "final", exposed.Rule)
}

func TestSensitiveTopDimensionRejected(t *testing.T) {
	manager := newTestManager(t, false)
	for _, dimension := range []string{"rule", "domain"} {
		request := httptest.NewRequest(http.MethodGet, "/top?dimension="+dimension, nil)
		response := httptest.NewRecorder()
		manager.Handler().ServeHTTP(response, request)
		require.Equal(t, http.StatusBadRequest, response.Code)
		require.Contains(t, response.Body.String(), "sensitive dimensions are disabled")
	}
}

func TestHandlerAcceptsMountedPrefix(t *testing.T) {
	manager := newTestManager(t, false)
	request := httptest.NewRequest(http.MethodGet, "/observability/v1/status", nil)
	response := httptest.NewRecorder()
	manager.Handler().ServeHTTP(response, request)
	require.Equal(t, http.StatusOK, response.Code)
}

func TestConfigurationLimits(t *testing.T) {
	traffic := trafficcontrol.NewManager(nil)
	_, err := New(context.Background(), log.NewNOPFactory().NewLogger("test"), traffic, option.ObservabilityOptions{
		RecentConnections: MaxRecentConnections + 1,
	})
	require.Error(t, err)
	_, err = New(context.Background(), log.NewNOPFactory().NewLogger("test"), traffic, option.ObservabilityOptions{
		TopKSize: MaxTopKSize + 1,
	})
	require.Error(t, err)
}

func TestConnectionCursorPagination(t *testing.T) {
	now := time.Now()
	connections := []Connection{
		{ID: "c", ClosedAt: now},
		{ID: "b", ClosedAt: now.Add(-time.Second)},
		{ID: "a", ClosedAt: now.Add(-2 * time.Second)},
	}
	first, err := paginateConnections(connections, "", 2, true)
	require.NoError(t, err)
	require.Equal(t, []string{"c", "b"}, []string{first.Data[0].ID, first.Data[1].ID})
	require.True(t, first.HasMore)
	require.NotEmpty(t, first.NextCursor)

	second, err := paginateConnections(connections, first.NextCursor, 2, true)
	require.NoError(t, err)
	require.Len(t, second.Data, 1)
	require.Equal(t, "a", second.Data[0].ID)
	require.False(t, second.HasMore)

	_, err = paginateConnections(connections, "invalid", 2, true)
	require.Error(t, err)
}

func TestConnectionCursorStableWhenNewItemArrives(t *testing.T) {
	now := time.Now()
	connections := []Connection{
		{ID: "b", ClosedAt: now},
		{ID: "a", ClosedAt: now.Add(-time.Second)},
	}
	first, err := paginateConnections(connections, "", 1, true)
	require.NoError(t, err)
	connections = append([]Connection{{ID: "c", ClosedAt: now.Add(time.Second)}}, connections...)
	second, err := paginateConnections(connections, first.NextCursor, 1, true)
	require.NoError(t, err)
	require.Equal(t, "a", second.Data[0].ID)
}

func TestTopDimensionHeap(t *testing.T) {
	result := make(dimensionHeap, 0, 2)
	for _, item := range []Dimension{
		{Value: "low", Download: 1},
		{Value: "second", Download: 20},
		{Value: "first", Upload: 30},
		{Value: "ignored", Download: 2},
	} {
		pushTopDimension(&result, item, 2)
	}
	require.ElementsMatch(t, []string{"first", "second"}, []string{result[0].Value, result[1].Value})
}

func TestCapabilitiesAndStructuredErrors(t *testing.T) {
	manager := newTestManager(t, true)
	request := httptest.NewRequest(http.MethodGet, "/capabilities", nil)
	response := httptest.NewRecorder()
	manager.Handler().ServeHTTP(response, request)
	require.Equal(t, http.StatusOK, response.Code)
	var capabilities Capabilities
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &capabilities))
	require.True(t, capabilities.CursorPagination)
	require.False(t, capabilities.EventReplay)
	require.True(t, capabilities.ExposeSensitive)

	request = httptest.NewRequest(http.MethodGet, "/connections/active?limit=501", nil)
	response = httptest.NewRecorder()
	manager.Handler().ServeHTTP(response, request)
	require.Equal(t, http.StatusBadRequest, response.Code)
	var apiError APIError
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &apiError))
	require.Equal(t, "invalid_query_parameter", apiError.Error.Code)
	require.Equal(t, "limit", apiError.Error.Parameter)
	var errorResponse map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &errorResponse))
	require.Len(t, errorResponse, 1)
	require.Contains(t, errorResponse, "error")

	request = httptest.NewRequest(http.MethodGet, "/connections/recent?offset=0", nil)
	response = httptest.NewRecorder()
	manager.Handler().ServeHTTP(response, request)
	require.Equal(t, http.StatusBadRequest, response.Code)
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &apiError))
	require.Equal(t, "unknown_query_parameter", apiError.Error.Code)
	require.Equal(t, "offset", apiError.Error.Parameter)
}

func TestObservabilityAPIMetrics(t *testing.T) {
	manager := newTestManager(t, false)
	request := httptest.NewRequest(http.MethodGet, "/status", nil)
	manager.Handler().ServeHTTP(httptest.NewRecorder(), request)
	request = httptest.NewRequest(http.MethodGet, "/metrics", nil)
	response := httptest.NewRecorder()
	manager.Handler().ServeHTTP(response, request)
	require.Contains(t, response.Body.String(), "singbox_observability_http_requests_total{endpoint=\"status\",status=\"200\"} 1")
	require.Contains(t, response.Body.String(), "singbox_recent_connections_capacity 1000")
}

func BenchmarkTopDimensionHeap(b *testing.B) {
	values := make([]Dimension, 100000)
	for index := range values {
		values[index] = Dimension{Value: "value", Download: int64(index)}
	}
	b.ResetTimer()
	for range b.N {
		result := make(dimensionHeap, 0, 100)
		for _, value := range values {
			pushTopDimension(&result, value, 100)
		}
	}
}

func newTestManager(t *testing.T, exposeSensitive bool) *Manager {
	t.Helper()
	service, err := New(context.Background(), log.NewNOPFactory().NewLogger("test"), trafficcontrol.NewManager(nil), option.ObservabilityOptions{
		ExposeSensitive: exposeSensitive,
	})
	require.NoError(t, err)
	return service.(*Manager)
}

func testMetadata() trafficcontrol.TrackerMetadata {
	upload := new(atomic.Int64)
	download := new(atomic.Int64)
	return trafficcontrol.TrackerMetadata{
		Metadata: adapter.InboundContext{
			Inbound:     "mixed-in",
			InboundType: "mixed",
			Network:     "tcp",
			Source:      M.Socksaddr{Addr: netip.MustParseAddr("192.0.2.1"), Port: 12345},
			Destination: M.Socksaddr{Addr: netip.MustParseAddr("198.51.100.2"), Port: 443},
			Domain:      "example.com",
		},
		Upload:       upload,
		Download:     download,
		Outbound:     "proxy",
		OutboundType: "direct",
	}
}
