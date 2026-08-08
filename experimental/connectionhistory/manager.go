//go:build with_connection_history

package connectionhistory

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/trafficcontrol"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/service/filemanager"
)

const (
	closeQueueSize = 8192
	openQueueSize  = 4096
	flushSize      = 256
)

var _ Service = (*Manager)(nil)

type counterState struct {
	upload   int64
	download int64
	record   Record
}

type Manager struct {
	ctx       context.Context
	logger    log.ContextLogger
	traffic   *trafficcontrol.Manager
	path      string
	uiPath    string
	retention time.Duration

	database     *database
	closeQueue   chan trafficcontrol.TrackerMetadata
	openQueue    chan trafficcontrol.TrackerMetadata
	done         chan struct{}
	loopDone     chan struct{}
	closeOnce    sync.Once
	started      atomic.Bool
	droppedOpen  atomic.Uint64
	droppedClose atomic.Uint64

	states         map[string]*counterState
	closed         map[string]time.Time
	pendingRecords []Record
	pendingTraffic map[aggregateKey]aggregate
	loopErr        error
}

func New(ctx context.Context, logger log.ContextLogger, traffic *trafficcontrol.Manager, options option.ConnectionHistoryOptions) (Service, error) {
	path := options.Path
	if path == "" {
		path = "history.db"
	}
	retention := time.Duration(options.Retention)
	if retention <= 0 {
		retention = 30 * 24 * time.Hour
	}
	var uiPath string
	if options.ExternalUI != "" {
		uiPath = filemanager.BasePath(ctx, options.ExternalUI)
	}
	return &Manager{
		ctx:            ctx,
		logger:         logger,
		traffic:        traffic,
		path:           filemanager.BasePath(ctx, path),
		uiPath:         uiPath,
		retention:      retention,
		closeQueue:     make(chan trafficcontrol.TrackerMetadata, closeQueueSize),
		openQueue:      make(chan trafficcontrol.TrackerMetadata, openQueueSize),
		done:           make(chan struct{}),
		loopDone:       make(chan struct{}),
		states:         make(map[string]*counterState),
		closed:         make(map[string]time.Time),
		pendingTraffic: make(map[aggregateKey]aggregate),
	}, nil
}

func (m *Manager) Name() string {
	return "connection history"
}

func (m *Manager) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateInitialize || m.started.Load() {
		return nil
	}
	database, err := openDatabase(m.ctx, m.path)
	if err != nil {
		return err
	}
	if err = database.Prune(time.Now().Add(-m.retention)); err != nil {
		database.Close()
		return err
	}
	m.database = database
	m.started.Store(true)
	go m.loop()
	m.traffic.SetConnectionHistorySink(m)
	m.logger.Info("connection history started at ", m.path)
	return nil
}

func (m *Manager) Close() error {
	var closeErr error
	m.closeOnce.Do(func() {
		if !m.started.Load() {
			return
		}
		m.traffic.SetConnectionHistorySink(nil)
		m.started.Store(false)
		close(m.done)
		<-m.loopDone
		closeErr = errors.Join(m.loopErr, m.database.Close())
	})
	return closeErr
}

func (m *Manager) ConnectionOpened(metadata trafficcontrol.TrackerMetadata) {
	if !m.started.Load() {
		return
	}
	select {
	case m.openQueue <- metadata:
	default:
		m.droppedOpen.Add(1)
	}
}

func (m *Manager) ConnectionClosed(metadata trafficcontrol.TrackerMetadata) {
	if !m.started.Load() {
		return
	}
	select {
	case m.closeQueue <- metadata:
	default:
		m.droppedClose.Add(1)
	}
}

func (m *Manager) ExternalUI() string {
	return m.uiPath
}

func (m *Manager) Summary(query Query) (Summary, error) {
	summary, err := m.database.Summary(query)
	if err == nil {
		summary.Active = m.traffic.ConnectionsLen()
	}
	return summary, err
}

func (m *Manager) Trend(query Query) ([]TrafficPoint, error) {
	return m.database.Trend(query)
}

func (m *Manager) Connections(query Query) (ConnectionPage, error) {
	return m.database.Connections(query)
}

func (m *Manager) Dimensions(name string, query Query) (DimensionPage, error) {
	return m.database.Dimensions(name, query)
}

func (m *Manager) Status() Status {
	var databaseSize int64
	if m.database != nil {
		databaseSize = m.database.Size()
	}
	return Status{
		DatabaseSize: databaseSize,
		Queued:       len(m.closeQueue) + len(m.openQueue),
		DroppedOpen:  m.droppedOpen.Load(),
		DroppedClose: m.droppedClose.Load(),
	}
}

func (m *Manager) loop() {
	defer close(m.loopDone)
	flushTicker := time.NewTicker(time.Second)
	sampleTicker := time.NewTicker(5 * time.Second)
	pruneTicker := time.NewTicker(time.Hour)
	defer flushTicker.Stop()
	defer sampleTicker.Stop()
	defer pruneTicker.Stop()

	for {
		select {
		case metadata := <-m.closeQueue:
			m.process(metadata, true)
		default:
			select {
			case metadata := <-m.closeQueue:
				m.process(metadata, true)
			case metadata := <-m.openQueue:
				m.processOpen(metadata)
			case <-sampleTicker.C:
				m.sampleActive()
			case <-flushTicker.C:
				m.flushAndLog()
			case <-pruneTicker.C:
				m.prune()
			case <-m.done:
				m.sampleActive()
				m.drain()
				m.loopErr = m.flush()
				return
			}
		}
		if len(m.pendingRecords) >= flushSize {
			m.flushAndLog()
		}
	}
}

func (m *Manager) drain() {
	for {
		drained := true
		select {
		case metadata := <-m.closeQueue:
			m.process(metadata, true)
			drained = false
		default:
		}
		select {
		case metadata := <-m.openQueue:
			m.processOpen(metadata)
			drained = false
		default:
		}
		if drained {
			return
		}
	}
}

func (m *Manager) sampleActive() {
	now := time.Now()
	for _, metadata := range m.traffic.Connections() {
		m.processAt(*metadata, false, now)
	}
	for id, closedAt := range m.closed {
		if now.Sub(closedAt) > 15*time.Second {
			delete(m.closed, id)
		}
	}
}

func (m *Manager) process(metadata trafficcontrol.TrackerMetadata, closed bool) {
	observedAt := time.Now()
	if closed && !metadata.ClosedAt.IsZero() {
		observedAt = metadata.ClosedAt
	} else if !closed && !metadata.CreatedAt.IsZero() {
		observedAt = metadata.CreatedAt
	}
	m.processAt(metadata, closed, observedAt)
}

func (m *Manager) processOpen(metadata trafficcontrol.TrackerMetadata) {
	id := metadata.ID.String()
	if _, loaded := m.closed[id]; loaded {
		return
	}
	if _, loaded := m.states[id]; loaded {
		return
	}
	record := recordFromMetadata(metadata)
	m.states[id] = &counterState{record: record}
	m.addTraffic(record, metadata.CreatedAt, 0, 0, 1)
}

func (m *Manager) processAt(metadata trafficcontrol.TrackerMetadata, closed bool, observedAt time.Time) {
	id := metadata.ID.String()
	if _, loaded := m.closed[id]; loaded && !closed {
		return
	}
	record := recordFromMetadata(metadata)
	state := m.states[id]
	var connectionDelta int64
	if state == nil {
		state = &counterState{record: record}
		m.states[id] = state
		connectionDelta = 1
	} else {
		state.record = record
	}
	upload := record.Upload - state.upload
	download := record.Download - state.download
	if upload < 0 {
		upload = record.Upload
	}
	if download < 0 {
		download = record.Download
	}
	state.upload = record.Upload
	state.download = record.Download
	m.addTraffic(record, observedAt, upload, download, connectionDelta)

	if closed {
		m.pendingRecords = append(m.pendingRecords, record)
		delete(m.states, id)
		m.closed[id] = time.Now()
	}
}

func (m *Manager) addTraffic(record Record, observedAt time.Time, upload int64, download int64, connections int64) {
	if upload == 0 && download == 0 && connections == 0 {
		return
	}
	minute := observedAt.UTC().Truncate(time.Minute).Unix()
	hour := observedAt.UTC().Truncate(time.Hour).Unix()
	outbound := strings.Join(record.Chain, " > ")
	if outbound == "" {
		outbound = record.Outbound
	}
	base := aggregateKey{
		Domain:   record.Domain,
		IP:       record.DestinationIP,
		Source:   record.SourceIP,
		Outbound: outbound,
		Rule:     record.Rule,
	}
	minuteKey := base
	minuteKey.Bucket = minute
	mergeAggregate(m.pendingTraffic, minuteKey, upload, download, connections)
	hourKey := base
	hourKey.Hour = true
	hourKey.Bucket = hour
	mergeAggregate(m.pendingTraffic, hourKey, upload, download, connections)
}

func (m *Manager) flush() error {
	if len(m.pendingRecords) == 0 && len(m.pendingTraffic) == 0 {
		return nil
	}
	if err := m.database.Write(m.pendingRecords, m.pendingTraffic); err != nil {
		return err
	}
	m.pendingRecords = m.pendingRecords[:0]
	m.pendingTraffic = make(map[aggregateKey]aggregate)
	return nil
}

func (m *Manager) flushAndLog() {
	if err := m.flush(); err != nil {
		m.logger.Error("write connection history: ", err)
	}
}

func (m *Manager) prune() {
	if err := m.database.Prune(time.Now().Add(-m.retention)); err != nil {
		m.logger.Error("prune connection history: ", err)
	}
}

func recordFromMetadata(metadata trafficcontrol.TrackerMetadata) Record {
	inbound := metadata.Metadata.InboundType
	if metadata.Metadata.Inbound != "" {
		inbound = metadata.Metadata.InboundType + "/" + metadata.Metadata.Inbound
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
	rule := "final"
	if metadata.Rule != nil {
		rule = F.ToString(metadata.Rule, " => ", metadata.Rule.Action())
	}
	var sourceIP string
	if metadata.Metadata.Source.Addr.IsValid() {
		sourceIP = metadata.Metadata.Source.Addr.String()
	}
	var destinationIP string
	if metadata.Metadata.Destination.Addr.IsValid() {
		destinationIP = metadata.Metadata.Destination.Addr.String()
	}
	return Record{
		ID:              metadata.ID.String(),
		Network:         metadata.Metadata.Network,
		Inbound:         inbound,
		SourceIP:        sourceIP,
		SourcePort:      metadata.Metadata.Source.Port,
		SourceMAC:       metadata.Metadata.SourceMACAddress.String(),
		SourceHostname:  metadata.Metadata.SourceHostname,
		DestinationIP:   destinationIP,
		DestinationPort: metadata.Metadata.Destination.Port,
		Domain:          domain,
		Process:         process,
		User:            metadata.Metadata.User,
		Outbound:        metadata.Outbound,
		OutboundType:    metadata.OutboundType,
		Chain:           append([]string(nil), metadata.Chain...),
		Rule:            rule,
		StartedAt:       metadata.CreatedAt,
		ClosedAt:        metadata.ClosedAt,
		Upload:          metadata.Upload.Load(),
		Download:        metadata.Download.Load(),
	}
}
