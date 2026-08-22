package observability

import (
	"context"
	"errors"
	"net/http"
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/trafficcontrol"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/service"
)

var (
	_ Service                           = (*Manager)(nil)
	_ trafficcontrol.ConnectionObserver = (*Manager)(nil)
)

type outboundStatistics struct {
	trafficcontrol.TrafficCounters
	connectionsTotal  atomic.Uint64
	activeConnections atomic.Int64
}

type connectionDimension struct {
	kind string
	name string
}

type connectionStatistics struct {
	connectionsTotal  atomic.Uint64
	activeConnections atomic.Int64
}

type Manager struct {
	ctx                  context.Context
	cancel               context.CancelFunc
	logger               log.ContextLogger
	traffic              *trafficcontrol.Manager
	outbound             adapter.OutboundManager
	urlTestHistory       *urltest.HistoryStorage
	startedAt            time.Time
	recentConnections    int
	recentTTL            time.Duration
	topKSize             int
	exposeSensitive      bool
	started              atomic.Bool
	connectionsTotal     atomic.Uint64
	statisticsAccess     sync.RWMutex
	outboundStatistics   map[string]*outboundStatistics
	connectionStatistics map[connectionDimension]*connectionStatistics
	topCacheAccess       sync.Mutex
	topCache             map[topCacheKey]topCacheEntry
	recentGeneration     atomic.Uint64
	apiMetrics           apiMetrics
	handler              httpHandler
}

func New(ctx context.Context, logger log.ContextLogger, traffic *trafficcontrol.Manager, options option.ObservabilityOptions) (Service, error) {
	recentConnections := options.RecentConnections
	if recentConnections <= 0 {
		recentConnections = DefaultRecentConnections
	} else if recentConnections > MaxRecentConnections {
		return nil, E.New("observability recent_connections must not exceed ", MaxRecentConnections)
	}
	recentTTL := time.Duration(options.RecentTTL)
	if recentTTL <= 0 {
		recentTTL = DefaultRecentTTL
	}
	topKSize := options.TopKSize
	if topKSize <= 0 {
		topKSize = DefaultTopKSize
	} else if topKSize > MaxTopKSize {
		return nil, E.New("observability top_k_size must not exceed ", MaxTopKSize)
	}
	ctx, cancel := context.WithCancel(ctx)
	manager := &Manager{
		ctx:                  ctx,
		cancel:               cancel,
		logger:               logger,
		traffic:              traffic,
		outbound:             service.FromContext[adapter.OutboundManager](ctx),
		urlTestHistory:       service.PtrFromContext[urltest.HistoryStorage](ctx),
		startedAt:            time.Now(),
		recentConnections:    recentConnections,
		recentTTL:            recentTTL,
		topKSize:             topKSize,
		exposeSensitive:      options.ExposeSensitive,
		outboundStatistics:   make(map[string]*outboundStatistics),
		connectionStatistics: make(map[connectionDimension]*connectionStatistics),
		topCache:             make(map[topCacheKey]topCacheEntry),
	}
	manager.handler.manager = manager
	return manager, nil
}

func (m *Manager) Name() string {
	return "observability"
}

func (m *Manager) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateInitialize || m.started.Swap(true) {
		return nil
	}
	m.startedAt = time.Now()
	m.traffic.SetClosedConnectionsLimit(m.recentConnections)
	m.traffic.SetConnectionObserver(m)
	m.logger.Info("observability started with ", m.recentConnections, " recent connections in memory")
	return nil
}

func (m *Manager) Close() error {
	m.cancel()
	if m.started.Swap(false) {
		m.traffic.SetConnectionObserver(nil)
	}
	return nil
}

func (m *Manager) Handler() http.Handler {
	return &m.handler
}

func (m *Manager) TrafficCounters(metadata trafficcontrol.TrackerMetadata) *trafficcontrol.TrafficCounters {
	return &m.statisticsFor(outboundName(metadata)).TrafficCounters
}

func (m *Manager) ConnectionOpened(metadata trafficcontrol.TrackerMetadata) {
	m.connectionsTotal.Add(1)
	statistics := m.statisticsFor(outboundName(metadata))
	statistics.connectionsTotal.Add(1)
	statistics.activeConnections.Add(1)
	for _, dimension := range connectionDimensions(metadata) {
		statistics := m.statisticsForDimension(dimension)
		statistics.connectionsTotal.Add(1)
		statistics.activeConnections.Add(1)
	}
}

func (m *Manager) ConnectionClosed(metadata trafficcontrol.TrackerMetadata) {
	m.recentGeneration.Add(1)
	statistics := m.statisticsFor(outboundName(metadata))
	statistics.activeConnections.Add(-1)
	for _, dimension := range connectionDimensions(metadata) {
		m.statisticsForDimension(dimension).activeConnections.Add(-1)
	}
}

func (m *Manager) statisticsFor(outbound string) *outboundStatistics {
	m.statisticsAccess.RLock()
	statistics := m.outboundStatistics[outbound]
	m.statisticsAccess.RUnlock()
	if statistics != nil {
		return statistics
	}
	m.statisticsAccess.Lock()
	statistics = m.outboundStatistics[outbound]
	if statistics == nil {
		statistics = new(outboundStatistics)
		m.outboundStatistics[outbound] = statistics
	}
	m.statisticsAccess.Unlock()
	return statistics
}

func (m *Manager) statisticsForDimension(dimension connectionDimension) *connectionStatistics {
	m.statisticsAccess.RLock()
	statistics := m.connectionStatistics[dimension]
	m.statisticsAccess.RUnlock()
	if statistics != nil {
		return statistics
	}
	m.statisticsAccess.Lock()
	statistics = m.connectionStatistics[dimension]
	if statistics == nil {
		statistics = new(connectionStatistics)
		m.connectionStatistics[dimension] = statistics
	}
	m.statisticsAccess.Unlock()
	return statistics
}

func (m *Manager) activeConnections(cursor string, limit int) (ConnectionPage, error) {
	metadata := m.traffic.Connections()
	connections := make([]Connection, 0, len(metadata))
	for _, item := range metadata {
		connections = append(connections, m.connectionFromMetadata(*item))
	}
	sortConnections(connections, false)
	return paginateConnections(connections, cursor, limit, false)
}

func (m *Manager) recentConnectionPage(cursor string, limit int, window time.Duration) (ConnectionPage, error) {
	if limit <= 0 || limit > m.recentConnections {
		limit = min(100, m.recentConnections)
	}
	window = m.normalizeWindow(window)
	cutoff := time.Now().Add(-window)
	metadata := m.traffic.ClosedConnections()
	connections := make([]Connection, 0, len(metadata))
	for _, item := range slices.Backward(metadata) {
		if item.ClosedAt.Before(cutoff) {
			break
		}
		connections = append(connections, m.connectionFromMetadata(*item))
	}
	sortConnections(connections, true)
	return paginateConnections(connections, cursor, limit, true)
}

func (m *Manager) recentConnectionCount(window time.Duration) int {
	cutoff := time.Now().Add(-m.normalizeWindow(window))
	metadata := m.traffic.ClosedConnections()
	count := 0
	for _, m := range slices.Backward(metadata) {
		if m.ClosedAt.Before(cutoff) {
			break
		}
		count++
	}
	return count
}

func (m *Manager) topDimensions(name string, window time.Duration, limit int) (DimensionPage, error) {
	if !validDimension(name) {
		return DimensionPage{}, E.New("unsupported dimension: ", name)
	}
	if !m.exposeSensitive && sensitiveDimension(name) {
		return DimensionPage{}, errors.New("sensitive dimensions are disabled")
	}
	if limit <= 0 || limit > m.topKSize {
		limit = m.topKSize
	}
	window = m.normalizeWindow(window)
	cacheKey := topCacheKey{name: name, window: window, limit: limit, generation: m.recentGeneration.Load()}
	m.topCacheAccess.Lock()
	if cached, loaded := m.topCache[cacheKey]; loaded && time.Since(cached.createdAt) < topCacheTTL {
		m.topCacheAccess.Unlock()
		return cached.page, nil
	}
	m.topCacheAccess.Unlock()
	cutoff := time.Now().Add(-window)
	values := make(map[string]*Dimension)
	metadata := m.traffic.ClosedConnections()
	for _, item := range slices.Backward(metadata) {
		if item.ClosedAt.Before(cutoff) {
			break
		}
		value := dimensionValue(*item, name)
		if value == "" {
			continue
		}
		dimension := values[value]
		if dimension == nil {
			dimension = &Dimension{Value: value}
			values[value] = dimension
		}
		dimension.Upload += item.Upload.Load()
		dimension.Download += item.Download.Load()
		dimension.Connections++
	}
	all := make(dimensionHeap, 0, min(limit, len(values)))
	for _, dimension := range values {
		pushTopDimension(&all, *dimension, limit)
	}
	sort.Slice(all, func(i, j int) bool { return dimensionBetter(all[i], all[j]) })
	page := DimensionPage{Dimension: name, Window: window.String(), Total: len(values), Data: []Dimension(all)}
	m.topCacheAccess.Lock()
	if len(m.topCache) >= 64 {
		clear(m.topCache)
	}
	m.topCache[cacheKey] = topCacheEntry{createdAt: time.Now(), page: page}
	m.topCacheAccess.Unlock()
	return page, nil
}

func (m *Manager) normalizeWindow(window time.Duration) time.Duration {
	if window <= 0 || window > m.recentTTL {
		return m.recentTTL
	}
	return window
}

func (m *Manager) status() Status {
	upload, download := m.traffic.Total()
	return Status{
		Version:               C.Version,
		UptimeSeconds:         time.Since(m.startedAt).Seconds(),
		MemoryBytes:           inuseMemory(),
		Goroutines:            runtime.NumGoroutine(),
		ActiveConnections:     m.traffic.ConnectionsLen(),
		RecentConnections:     m.recentConnectionCount(m.recentTTL),
		ConnectionsTotal:      m.connectionsTotal.Load(),
		UploadBytesTotal:      upload,
		DownloadBytesTotal:    download,
		RecentConnectionLimit: m.recentConnections,
		RecentTTL:             m.recentTTL.String(),
		TopKSize:              m.topKSize,
		ExposeSensitive:       m.exposeSensitive,
	}
}

func (m *Manager) capabilities() Capabilities {
	return Capabilities{
		APIVersion:          1,
		Endpoints:           []string{"capabilities", "metrics", "status", "connections/active", "connections/recent", "events", "top"},
		TopDimensions:       []string{"network", "inbound", "outbound", "rule", "domain", "destination_ip", "source", "process", "user"},
		SensitiveDimensions: []string{"rule", "domain", "destination_ip", "source", "process", "user"},
		ExposeSensitive:     m.exposeSensitive,
		RecentLimit:         m.recentConnections,
		RecentTTL:           m.recentTTL.String(),
		TopKLimit:           m.topKSize,
		ActivePageLimit:     MaxActivePageSize,
		CursorPagination:    true,
		EventReplay:         false,
	}
}

func (m *Manager) streamEvents(ctx context.Context, heartbeat time.Duration, send func(*Event) error) error {
	subscription, done, err := m.traffic.SubscribeEvents()
	if err != nil {
		return err
	}
	defer m.traffic.UnSubscribeEvents(subscription)
	if heartbeat <= 0 {
		heartbeat = 15 * time.Second
	}
	ticker := time.NewTicker(heartbeat)
	defer ticker.Stop()
	var sequence uint64
	for {
		select {
		case <-m.ctx.Done():
			return m.ctx.Err()
		case <-ctx.Done():
			return ctx.Err()
		case <-done:
			return nil
		case event, loaded := <-subscription:
			if !loaded {
				return nil
			}
			eventType := "open"
			if event.Type == trafficcontrol.ConnectionEventClosed {
				eventType = "close"
			}
			if event.Metadata != nil {
				sequence++
				if err = send(&Event{ID: sequence, Type: eventType, Connection: m.connectionFromMetadata(*event.Metadata)}); err != nil {
					return err
				}
			}
		case <-ticker.C:
			if err = send(nil); err != nil {
				return err
			}
		}
	}
}

func (m *Manager) connectionFromMetadata(metadata trafficcontrol.TrackerMetadata) Connection {
	inbound := metadata.Metadata.InboundType
	if metadata.Metadata.Inbound != "" {
		inbound += "/" + metadata.Metadata.Inbound
	}
	domain := metadata.Metadata.Domain
	if domain == "" {
		domain = metadata.Metadata.Destination.Fqdn
	}
	var process string
	if processInfo := metadata.Metadata.ProcessInfo; processInfo != nil {
		process = processInfo.ProcessPath
		if process == "" && len(processInfo.AndroidPackageNames) > 0 {
			process = processInfo.AndroidPackageNames[0]
		}
	}
	connection := Connection{
		ID:              metadata.ID.String(),
		Network:         metadata.Metadata.Network,
		Inbound:         inbound,
		DestinationPort: metadata.Metadata.Destination.Port,
		Outbound:        metadata.Outbound,
		OutboundType:    metadata.OutboundType,
		Chain:           append([]string(nil), metadata.Chain...),
		StartedAt:       metadata.CreatedAt,
		ClosedAt:        metadata.ClosedAt,
		Upload:          metadata.Upload.Load(),
		Download:        metadata.Download.Load(),
	}
	if m.exposeSensitive {
		if metadata.Metadata.Source.Addr.IsValid() {
			connection.SourceIP = metadata.Metadata.Source.Addr.String()
		}
		if metadata.Metadata.Destination.Addr.IsValid() {
			connection.DestinationIP = metadata.Metadata.Destination.Addr.String()
		}
		connection.SourcePort = metadata.Metadata.Source.Port
		connection.SourceMAC = metadata.Metadata.SourceMACAddress.String()
		connection.SourceHostname = metadata.Metadata.SourceHostname
		connection.Domain = domain
		connection.Process = process
		connection.User = metadata.Metadata.User
		connection.Rule = "final"
		if metadata.Rule != nil {
			connection.Rule = F.ToString(metadata.Rule, " => ", metadata.Rule.Action())
		}
	}
	return connection
}

func outboundName(metadata trafficcontrol.TrackerMetadata) string {
	if len(metadata.Chain) > 0 {
		return strings.Join(metadata.Chain, " > ")
	}
	if metadata.Outbound != "" {
		return metadata.Outbound
	}
	return "unknown"
}

func connectionDimensions(metadata trafficcontrol.TrackerMetadata) []connectionDimension {
	inbound := metadata.Metadata.InboundType
	if metadata.Metadata.Inbound != "" {
		inbound += "/" + metadata.Metadata.Inbound
	}
	return []connectionDimension{
		{kind: "network", name: metadata.Metadata.Network},
		{kind: "inbound", name: inbound},
	}
}

func validDimension(name string) bool {
	switch name {
	case "network", "inbound", "outbound", "rule", "domain", "destination_ip", "source", "process", "user":
		return true
	default:
		return false
	}
}

func sensitiveDimension(name string) bool {
	switch name {
	case "rule", "domain", "destination_ip", "source", "process", "user":
		return true
	default:
		return false
	}
}

func dimensionValue(metadata trafficcontrol.TrackerMetadata, name string) string {
	switch name {
	case "network":
		return metadata.Metadata.Network
	case "inbound":
		if metadata.Metadata.Inbound != "" {
			return metadata.Metadata.InboundType + "/" + metadata.Metadata.Inbound
		}
		return metadata.Metadata.InboundType
	case "outbound":
		return outboundName(metadata)
	case "rule":
		if metadata.Rule == nil {
			return "final"
		}
		return F.ToString(metadata.Rule, " => ", metadata.Rule.Action())
	case "domain":
		if metadata.Metadata.Domain != "" {
			return metadata.Metadata.Domain
		}
		return metadata.Metadata.Destination.Fqdn
	case "destination_ip":
		if metadata.Metadata.Destination.Addr.IsValid() {
			return metadata.Metadata.Destination.Addr.String()
		}
	case "source":
		if metadata.Metadata.SourceHostname != "" {
			return metadata.Metadata.SourceHostname
		}
		if metadata.Metadata.Source.Addr.IsValid() {
			return metadata.Metadata.Source.Addr.String()
		}
	case "process":
		if metadata.Metadata.ProcessInfo != nil {
			if metadata.Metadata.ProcessInfo.ProcessPath != "" {
				return metadata.Metadata.ProcessInfo.ProcessPath
			}
			if len(metadata.Metadata.ProcessInfo.AndroidPackageNames) > 0 {
				return metadata.Metadata.ProcessInfo.AndroidPackageNames[0]
			}
		}
	case "user":
		return metadata.Metadata.User
	}
	return ""
}

func inuseMemory() uint64 {
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	return memory.StackInuse + memory.HeapInuse + memory.HeapIdle - memory.HeapReleased
}
