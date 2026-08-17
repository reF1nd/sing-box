//go:build with_ebpf && ebpf_debug && (linux || android)

package ebpf

import (
	"errors"
	"net"
	"net/http"
	httpPProf "net/http/pprof"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/log"
	E "github.com/sagernet/sing/common/exceptions"
)

const (
	ebpfRuntimeStatusInterval = time.Minute
	ebpfDebugPProfPortEnv     = "SING_BOX_EBPF_PPROF_PORT"
)

type eBPFDebugState struct {
	localTCPRedirectSweep     eBPFDebugTaskMetric
	sharedFlowPressurePoll    eBPFDebugTaskMetric
	sharedFlowSweep           eBPFDebugTaskMetric
	sharedAttachmentReconcile eBPFDebugTaskMetric
	ipv6RouteProbe            eBPFDebugTaskMetric
	runtimeStatusCollection   eBPFDebugTaskMetric
	localUDPBindingMiss       eBPFDebugUDPBindingMissMetric
	sharedUDPBindingMiss      eBPFDebugUDPBindingMissMetric
}

type eBPFDebugUDPWriterState struct {
	missed atomic.Bool
}

type eBPFDebugUDPBindingMissMetric struct {
	connectedPackets    atomic.Uint64
	unconnectedPackets  atomic.Uint64
	connectedSessions   atomic.Uint64
	unconnectedSessions atomic.Uint64
	warnings            warningLimiter
}

type eBPFDebugUDPBindingMissPathSnapshot struct {
	ConnectedPackets    uint64 `json:"connected_packets"`
	UnconnectedPackets  uint64 `json:"unconnected_packets"`
	ConnectedSessions   uint64 `json:"connected_sessions"`
	UnconnectedSessions uint64 `json:"unconnected_sessions"`
}

type eBPFDebugUDPBindingMissSnapshot struct {
	Local  eBPFDebugUDPBindingMissPathSnapshot `json:"local"`
	Shared eBPFDebugUDPBindingMissPathSnapshot `json:"shared"`
}

type eBPFDebugTaskMetric struct {
	runs               atomic.Uint64
	errors             atomic.Uint64
	totalDurationNanos atomic.Uint64
	maxDurationNanos   atomic.Uint64
	lastDurationNanos  atomic.Uint64
}

type eBPFDebugTaskSnapshot struct {
	Runs               uint64 `json:"runs"`
	Errors             uint64 `json:"errors"`
	TotalDurationNanos uint64 `json:"total_duration_ns"`
	MaxDurationNanos   uint64 `json:"max_duration_ns"`
	LastDurationNanos  uint64 `json:"last_duration_ns"`
}

type eBPFDebugGoRuntimeSnapshot struct {
	Goroutines        int    `json:"goroutines"`
	HeapAllocBytes    uint64 `json:"heap_alloc_bytes"`
	HeapInuseBytes    uint64 `json:"heap_inuse_bytes"`
	HeapObjects       uint64 `json:"heap_objects"`
	StackInuseBytes   uint64 `json:"stack_inuse_bytes"`
	SysBytes          uint64 `json:"sys_bytes"`
	RSSBytes          uint64 `json:"rss_bytes,omitempty"`
	RSSKnown          bool   `json:"rss_known"`
	GCCount           uint32 `json:"gc_count"`
	GCPauseTotalNanos uint64 `json:"gc_pause_total_ns"`
}

type eBPFDebugSnapshot struct {
	Build          bool                             `json:"build"`
	GoRuntime      eBPFDebugGoRuntimeSnapshot       `json:"go_runtime"`
	Maintenance    map[string]eBPFDebugTaskSnapshot `json:"maintenance"`
	UDPBindingMiss eBPFDebugUDPBindingMissSnapshot  `json:"udp_binding_miss"`
}

func (d *eBPFDebugState) observe(task string, duration time.Duration, err error) {
	metric := d.metric(task)
	if metric == nil {
		return
	}
	durationNanos := uint64(max(duration.Nanoseconds(), 0))
	metric.runs.Add(1)
	if err != nil {
		metric.errors.Add(1)
	}
	metric.totalDurationNanos.Add(durationNanos)
	metric.lastDurationNanos.Store(durationNanos)
	for previous := metric.maxDurationNanos.Load(); durationNanos > previous; previous = metric.maxDurationNanos.Load() {
		if metric.maxDurationNanos.CompareAndSwap(previous, durationNanos) {
			break
		}
	}
}

func (d *eBPFDebugState) metric(task string) *eBPFDebugTaskMetric {
	switch task {
	case ebpfDebugTaskLocalTCPRedirectSweep:
		return &d.localTCPRedirectSweep
	case ebpfDebugTaskSharedFlowPressurePoll:
		return &d.sharedFlowPressurePoll
	case ebpfDebugTaskSharedFlowSweep:
		return &d.sharedFlowSweep
	case ebpfDebugTaskSharedAttachmentReconcile:
		return &d.sharedAttachmentReconcile
	case ebpfDebugTaskIPv6RouteProbe:
		return &d.ipv6RouteProbe
	case ebpfDebugTaskRuntimeStatusCollection:
		return &d.runtimeStatusCollection
	default:
		return nil
	}
}

func (m *eBPFDebugTaskMetric) snapshot() eBPFDebugTaskSnapshot {
	return eBPFDebugTaskSnapshot{
		Runs:               m.runs.Load(),
		Errors:             m.errors.Load(),
		TotalDurationNanos: m.totalDurationNanos.Load(),
		MaxDurationNanos:   m.maxDurationNanos.Load(),
		LastDurationNanos:  m.lastDurationNanos.Load(),
	}
}

func (m *eBPFDebugUDPBindingMissMetric) observe(writer *eBPFDebugUDPWriterState, connected bool) bool {
	if connected {
		m.connectedPackets.Add(1)
	} else {
		m.unconnectedPackets.Add(1)
	}
	if !writer.missed.CompareAndSwap(false, true) {
		return false
	}
	if connected {
		m.connectedSessions.Add(1)
	} else {
		m.unconnectedSessions.Add(1)
	}
	return true
}

func (m *eBPFDebugUDPBindingMissMetric) snapshot() eBPFDebugUDPBindingMissPathSnapshot {
	return eBPFDebugUDPBindingMissPathSnapshot{
		ConnectedPackets:    m.connectedPackets.Load(),
		UnconnectedPackets:  m.unconnectedPackets.Load(),
		ConnectedSessions:   m.connectedSessions.Load(),
		UnconnectedSessions: m.unconnectedSessions.Load(),
	}
}

func (d *eBPFDebugState) observeUDPBindingMiss(
	writer *eBPFDebugUDPWriterState,
	shared bool,
	logger log.ContextLogger,
	table *udpClientTable,
	client netip.AddrPort,
	destination netip.AddrPort,
	state *udpClientState,
) {
	metric := &d.localUDPBindingMiss
	path := "local"
	if shared {
		metric = &d.sharedUDPBindingMiss
		path = "shared"
	}
	state.access.RLock()
	connected := state.connected
	connectedDestination := state.connectedDestination
	bindingCount := len(state.bindings)
	originalCount := len(state.originals)
	state.access.RUnlock()
	if !metric.observe(writer, connected) || logger == nil {
		return
	}
	currentState, loaded := table.load(client)
	allowed, suppressed := metric.warnings.allow(time.Now())
	if !allowed {
		return
	}
	args := []any{
		"eBPF debug UDP binding miss: path=", path,
		" client=", client,
		" requested_destination=", destination,
		" connected=", connected,
		" connected_destination=", connectedDestination,
		" bindings=", bindingCount,
		" originals=", originalCount,
		" state_current=", loaded && currentState == state,
	}
	if suppressed > 0 {
		args = append(args, " (", suppressed, " unique sessions suppressed)")
	}
	logger.Debug(args...)
}

func (d *eBPFDebugState) snapshot() *eBPFDebugSnapshot {
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	rssBytes, rssKnown := readProcessRSS()
	return &eBPFDebugSnapshot{
		Build: true,
		GoRuntime: eBPFDebugGoRuntimeSnapshot{
			Goroutines:        runtime.NumGoroutine(),
			HeapAllocBytes:    memory.HeapAlloc,
			HeapInuseBytes:    memory.HeapInuse,
			HeapObjects:       memory.HeapObjects,
			StackInuseBytes:   memory.StackInuse,
			SysBytes:          memory.Sys,
			RSSBytes:          rssBytes,
			RSSKnown:          rssKnown,
			GCCount:           memory.NumGC,
			GCPauseTotalNanos: memory.PauseTotalNs,
		},
		Maintenance: map[string]eBPFDebugTaskSnapshot{
			ebpfDebugTaskLocalTCPRedirectSweep:     d.localTCPRedirectSweep.snapshot(),
			ebpfDebugTaskSharedFlowPressurePoll:    d.sharedFlowPressurePoll.snapshot(),
			ebpfDebugTaskSharedFlowSweep:           d.sharedFlowSweep.snapshot(),
			ebpfDebugTaskSharedAttachmentReconcile: d.sharedAttachmentReconcile.snapshot(),
			ebpfDebugTaskIPv6RouteProbe:            d.ipv6RouteProbe.snapshot(),
			ebpfDebugTaskRuntimeStatusCollection:   d.runtimeStatusCollection.snapshot(),
		},
		UDPBindingMiss: eBPFDebugUDPBindingMissSnapshot{
			Local:  d.localUDPBindingMiss.snapshot(),
			Shared: d.sharedUDPBindingMiss.snapshot(),
		},
	}
}

func readProcessRSS() (uint64, bool) {
	contents, err := os.ReadFile("/proc/self/statm")
	if err != nil {
		return 0, false
	}
	fields := strings.Fields(string(contents))
	if len(fields) < 2 {
		return 0, false
	}
	residentPages, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return 0, false
	}
	return residentPages * uint64(os.Getpagesize()), true
}

func ebpfRuntimeStatusReporterEnabled(logger log.ContextLogger) bool {
	return ebpfDebugLoggingEnabled(logger)
}

type eBPFDebugPProfServer struct {
	server     *http.Server
	listener   net.Listener
	port       string
	references int
}

var (
	ebpfDebugPProfAccess sync.Mutex
	ebpfDebugPProf       *eBPFDebugPProfServer
)

func acquireEBPFDebugPProf(logger log.ContextLogger) (func(), error) {
	port := os.Getenv(ebpfDebugPProfPortEnv)
	if port == "" {
		return nil, nil
	}
	parsedPort, err := strconv.ParseUint(port, 10, 16)
	if err != nil || parsedPort == 0 {
		return nil, E.New("invalid ", ebpfDebugPProfPortEnv, ": ", port)
	}
	port = strconv.FormatUint(parsedPort, 10)
	ebpfDebugPProfAccess.Lock()
	defer ebpfDebugPProfAccess.Unlock()
	if ebpfDebugPProf != nil {
		if ebpfDebugPProf.port != port {
			return nil, E.New("eBPF debug pprof is already listening on port ", ebpfDebugPProf.port)
		}
		ebpfDebugPProf.references++
		return releaseEBPFDebugPProfFunc(), nil
	}
	address := net.JoinHostPort("127.0.0.1", port)
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, err
	}
	server := &http.Server{
		Addr:              address,
		Handler:           newEBPFDebugPProfMux(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	ebpfDebugPProf = &eBPFDebugPProfServer{
		server:     server,
		listener:   listener,
		port:       port,
		references: 1,
	}
	go func() {
		if serveErr := server.Serve(listener); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			logger.Warn("serve eBPF debug pprof: ", serveErr)
		}
	}()
	logger.Info("eBPF debug pprof listening on http://", address, "/debug/pprof/")
	return releaseEBPFDebugPProfFunc(), nil
}

func releaseEBPFDebugPProfFunc() func() {
	var once sync.Once
	return func() {
		once.Do(releaseEBPFDebugPProf)
	}
}

func releaseEBPFDebugPProf() {
	ebpfDebugPProfAccess.Lock()
	defer ebpfDebugPProfAccess.Unlock()
	if ebpfDebugPProf == nil {
		return
	}
	ebpfDebugPProf.references--
	if ebpfDebugPProf.references > 0 {
		return
	}
	_ = ebpfDebugPProf.server.Close()
	_ = ebpfDebugPProf.listener.Close()
	ebpfDebugPProf = nil
}

func newEBPFDebugPProfMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", httpPProf.Index)
	mux.HandleFunc("/debug/pprof/cmdline", httpPProf.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", httpPProf.Profile)
	mux.HandleFunc("/debug/pprof/symbol", httpPProf.Symbol)
	mux.HandleFunc("/debug/pprof/trace", httpPProf.Trace)
	for _, profile := range []string{"allocs", "block", "goroutine", "heap", "mutex", "threadcreate"} {
		mux.Handle("/debug/pprof/"+profile, httpPProf.Handler(profile))
	}
	return mux
}

func logEBPFDebugBuild(logger log.ContextLogger) {
	logger.Info(
		"eBPF debug instrumentation enabled: runtime_status_interval=", ebpfRuntimeStatusInterval,
		", pprof_env=", ebpfDebugPProfPortEnv,
	)
}
