package observability

import (
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

type apiMetricKey struct {
	endpoint string
	status   int
}

type apiMetricValue struct {
	requests uint64
	bytes    uint64
	duration time.Duration
}

type apiMetricSample struct {
	key   apiMetricKey
	value apiMetricValue
}

type apiMetrics struct {
	access         sync.Mutex
	values         map[apiMetricKey]apiMetricValue
	sseSubscribers atomic.Int64
	sseEvents      atomic.Uint64
}

func (m *apiMetrics) observe(endpoint string, status int, bytes int, duration time.Duration) {
	m.access.Lock()
	if m.values == nil {
		m.values = make(map[apiMetricKey]apiMetricValue)
	}
	key := apiMetricKey{endpoint: endpoint, status: status}
	value := m.values[key]
	value.requests++
	value.bytes += uint64(max(bytes, 0))
	value.duration += duration
	m.values[key] = value
	m.access.Unlock()
}

func (m *apiMetrics) snapshot() []apiMetricSample {
	m.access.Lock()
	result := make([]apiMetricSample, 0, len(m.values))
	for key, value := range m.values {
		result = append(result, apiMetricSample{key: key, value: value})
	}
	m.access.Unlock()
	sort.Slice(result, func(i, j int) bool {
		if result[i].key.endpoint == result[j].key.endpoint {
			return result[i].key.status < result[j].key.status
		}
		return result[i].key.endpoint < result[j].key.endpoint
	})
	return result
}

func apiMetricLabels(sample apiMetricSample) string {
	return "endpoint=\"" + prometheusEscape(sample.key.endpoint) + "\",status=\"" + strconv.Itoa(sample.key.status) + "\""
}
