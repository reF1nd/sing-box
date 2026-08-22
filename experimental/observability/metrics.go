package observability

import (
	"bufio"
	"fmt"
	"io"
	"runtime"
	"sort"
	"strconv"
	"strings"
)

type namedStatistics struct {
	name       string
	statistics *outboundStatistics
}

type namedConnectionStatistics struct {
	name       string
	statistics *connectionStatistics
}

type urlTestStatistics struct {
	name      string
	delay     uint16
	timestamp int64
}

func (m *Manager) writePrometheus(writer io.Writer) error {
	output := bufio.NewWriter(writer)
	status := m.status()
	writeHelpAndType(output, "singbox_build_info", "Build information for the running sing-box instance.", "gauge")
	fmt.Fprintf(output, "singbox_build_info{version=\"%s\",go_version=\"%s\",os=\"%s\",arch=\"%s\"} 1\n", prometheusEscape(status.Version), prometheusEscape(runtime.Version()), runtime.GOOS, runtime.GOARCH)
	writeHelpAndType(output, "singbox_uptime_seconds", "Time since the observability service started.", "gauge")
	writeFloatMetric(output, "singbox_uptime_seconds", status.UptimeSeconds)
	writeHelpAndType(output, "singbox_memory_bytes", "Memory obtained from the OS and currently retained by the Go runtime.", "gauge")
	writeIntegerMetric(output, "singbox_memory_bytes", int64(status.MemoryBytes))
	writeHelpAndType(output, "singbox_goroutines", "Current number of goroutines.", "gauge")
	writeIntegerMetric(output, "singbox_goroutines", int64(status.Goroutines))
	writeHelpAndType(output, "singbox_connections_active", "Current number of active tracked connections.", "gauge")
	writeIntegerMetric(output, "singbox_connections_active", int64(status.ActiveConnections))
	writeHelpAndType(output, "singbox_connections_total", "Tracked connections opened since the observability service started.", "counter")
	writeIntegerMetric(output, "singbox_connections_total", int64(status.ConnectionsTotal))
	writeHelpAndType(output, "singbox_traffic_upload_bytes_total", "Bytes uploaded since sing-box started.", "counter")
	writeIntegerMetric(output, "singbox_traffic_upload_bytes_total", status.UploadBytesTotal)
	writeHelpAndType(output, "singbox_traffic_download_bytes_total", "Bytes downloaded since sing-box started.", "counter")
	writeIntegerMetric(output, "singbox_traffic_download_bytes_total", status.DownloadBytesTotal)
	writeHelpAndType(output, "singbox_recent_connections", "Closed connections currently retained in memory.", "gauge")
	writeIntegerMetric(output, "singbox_recent_connections", int64(status.RecentConnections))
	writeHelpAndType(output, "singbox_recent_connections_capacity", "Configured maximum number of closed connections retained in memory.", "gauge")
	writeIntegerMetric(output, "singbox_recent_connections_capacity", int64(status.RecentConnectionLimit))

	statistics := m.statisticsSnapshot()
	writeHelpAndType(output, "singbox_outbound_connections_active", "Current active connections grouped by outbound chain.", "gauge")
	for _, item := range statistics {
		writeLabeledIntegerMetric(output, "singbox_outbound_connections_active", item.name, item.statistics.activeConnections.Load())
	}
	writeHelpAndType(output, "singbox_outbound_connections_total", "Connections opened since observability started grouped by outbound chain.", "counter")
	for _, item := range statistics {
		writeLabeledIntegerMetric(output, "singbox_outbound_connections_total", item.name, int64(item.statistics.connectionsTotal.Load()))
	}
	writeHelpAndType(output, "singbox_outbound_upload_bytes_total", "Bytes uploaded grouped by outbound chain.", "counter")
	for _, item := range statistics {
		writeLabeledIntegerMetric(output, "singbox_outbound_upload_bytes_total", item.name, item.statistics.UploadBytes.Load())
	}
	writeHelpAndType(output, "singbox_outbound_download_bytes_total", "Bytes downloaded grouped by outbound chain.", "counter")
	for _, item := range statistics {
		writeLabeledIntegerMetric(output, "singbox_outbound_download_bytes_total", item.name, item.statistics.DownloadBytes.Load())
	}
	m.writeConnectionDimensionMetrics(output, "network", "singbox_network")
	m.writeConnectionDimensionMetrics(output, "inbound", "singbox_inbound")
	urlTests := m.urlTestSnapshot()
	writeHelpAndType(output, "singbox_outbound_urltest_delay_milliseconds", "Latest URL test delay for an outbound.", "gauge")
	for _, item := range urlTests {
		writeLabeledIntegerMetric(output, "singbox_outbound_urltest_delay_milliseconds", item.name, int64(item.delay))
	}
	writeHelpAndType(output, "singbox_outbound_urltest_timestamp_seconds", "Unix timestamp of the latest outbound URL test.", "gauge")
	for _, item := range urlTests {
		writeLabeledIntegerMetric(output, "singbox_outbound_urltest_timestamp_seconds", item.name, item.timestamp)
	}
	m.writeAPIMetrics(output)
	return output.Flush()
}

func (m *Manager) writeAPIMetrics(writer io.Writer) {
	samples := m.apiMetrics.snapshot()
	writeHelpAndType(writer, "singbox_observability_http_requests_total", "Observability API requests grouped by endpoint and HTTP status.", "counter")
	for _, sample := range samples {
		fmt.Fprintf(writer, "singbox_observability_http_requests_total{%s} %d\n", apiMetricLabels(sample), sample.value.requests)
	}
	writeHelpAndType(writer, "singbox_observability_http_response_bytes_total", "Observability API response bytes grouped by endpoint and HTTP status.", "counter")
	for _, sample := range samples {
		fmt.Fprintf(writer, "singbox_observability_http_response_bytes_total{%s} %d\n", apiMetricLabels(sample), sample.value.bytes)
	}
	writeHelpAndType(writer, "singbox_observability_http_request_duration_seconds_total", "Total observability API request duration grouped by endpoint and HTTP status.", "counter")
	for _, sample := range samples {
		fmt.Fprintf(writer, "singbox_observability_http_request_duration_seconds_total{%s} %s\n", apiMetricLabels(sample), strconv.FormatFloat(sample.value.duration.Seconds(), 'f', 6, 64))
	}
	writeHelpAndType(writer, "singbox_observability_sse_subscribers", "Current observability event stream subscribers.", "gauge")
	writeIntegerMetric(writer, "singbox_observability_sse_subscribers", m.apiMetrics.sseSubscribers.Load())
	writeHelpAndType(writer, "singbox_observability_sse_events_total", "Connection events sent to observability event stream subscribers.", "counter")
	writeIntegerMetric(writer, "singbox_observability_sse_events_total", int64(m.apiMetrics.sseEvents.Load()))
}

func (m *Manager) writeConnectionDimensionMetrics(writer io.Writer, kind string, prefix string) {
	statistics := m.connectionStatisticsSnapshot(kind)
	writeHelpAndType(writer, prefix+"_connections_active", "Current active connections grouped by "+kind+".", "gauge")
	for _, item := range statistics {
		writeNamedLabeledIntegerMetric(writer, prefix+"_connections_active", kind, item.name, item.statistics.activeConnections.Load())
	}
	writeHelpAndType(writer, prefix+"_connections_total", "Connections opened since observability started grouped by "+kind+".", "counter")
	for _, item := range statistics {
		writeNamedLabeledIntegerMetric(writer, prefix+"_connections_total", kind, item.name, int64(item.statistics.connectionsTotal.Load()))
	}
}

func (m *Manager) statisticsSnapshot() []namedStatistics {
	m.statisticsAccess.RLock()
	result := make([]namedStatistics, 0, len(m.outboundStatistics))
	for name, statistics := range m.outboundStatistics {
		result = append(result, namedStatistics{name: name, statistics: statistics})
	}
	m.statisticsAccess.RUnlock()
	sort.Slice(result, func(i, j int) bool { return result[i].name < result[j].name })
	return result
}

func (m *Manager) connectionStatisticsSnapshot(kind string) []namedConnectionStatistics {
	m.statisticsAccess.RLock()
	result := make([]namedConnectionStatistics, 0, len(m.connectionStatistics))
	for dimension, statistics := range m.connectionStatistics {
		if dimension.kind == kind && dimension.name != "" {
			result = append(result, namedConnectionStatistics{name: dimension.name, statistics: statistics})
		}
	}
	m.statisticsAccess.RUnlock()
	sort.Slice(result, func(i, j int) bool { return result[i].name < result[j].name })
	return result
}

func (m *Manager) urlTestSnapshot() []urlTestStatistics {
	if m.outbound == nil || m.urlTestHistory == nil {
		return nil
	}
	var result []urlTestStatistics
	for _, outbound := range m.outbound.Outbounds() {
		history := m.urlTestHistory.LoadURLTestHistory(outbound.Tag())
		if history == nil {
			continue
		}
		result = append(result, urlTestStatistics{
			name:      outbound.Tag(),
			delay:     history.Delay,
			timestamp: history.Time.Unix(),
		})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].name < result[j].name })
	return result
}

func writeHelpAndType(writer io.Writer, name string, help string, metricType string) {
	fmt.Fprintf(writer, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, metricType)
}

func writeIntegerMetric(writer io.Writer, name string, value int64) {
	fmt.Fprintf(writer, "%s %d\n", name, value)
}

func writeFloatMetric(writer io.Writer, name string, value float64) {
	fmt.Fprintf(writer, "%s %s\n", name, strconv.FormatFloat(value, 'f', 3, 64))
}

func writeLabeledIntegerMetric(writer io.Writer, name string, outbound string, value int64) {
	writeNamedLabeledIntegerMetric(writer, name, "outbound", outbound, value)
}

func writeNamedLabeledIntegerMetric(writer io.Writer, name string, label string, labelValue string, value int64) {
	fmt.Fprintf(writer, "%s{%s=\"%s\"} %d\n", name, label, prometheusEscape(labelValue), value)
}

func prometheusEscape(value string) string {
	value = strings.ReplaceAll(value, "\\", "\\\\")
	value = strings.ReplaceAll(value, "\n", "\\n")
	return strings.ReplaceAll(value, "\"", "\\\"")
}
