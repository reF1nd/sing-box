//go:build with_ebpf && !ebpf_debug && (linux || android)

package ebpf

import (
	"net/netip"
	"time"

	"github.com/sagernet/sing-box/log"
)

const ebpfRuntimeStatusInterval = 10 * time.Minute

type eBPFDebugState struct{}

type eBPFDebugSnapshot struct{}

type eBPFDebugUDPWriterState struct{}

func (d *eBPFDebugState) observe(task string, duration time.Duration, err error) {}

func (d *eBPFDebugState) snapshot() *eBPFDebugSnapshot { return nil }

func (d *eBPFDebugState) observeUDPBindingMiss(
	writer *eBPFDebugUDPWriterState,
	shared bool,
	logger log.ContextLogger,
	table *udpClientTable,
	client netip.AddrPort,
	destination netip.AddrPort,
	state *udpClientState,
) {
}

func ebpfRuntimeStatusReporterEnabled(logger log.ContextLogger) bool {
	return ebpfDebugLoggingEnabled(logger)
}

func acquireEBPFDebugPProf(logger log.ContextLogger) (func(), error) { return nil, nil }

func logEBPFDebugBuild(logger log.ContextLogger) {}
