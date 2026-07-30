//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"time"

	ECommon "github.com/sagernet/sing-box/common/ebpf"
)

const runtimeStatsInterval = 5 * time.Minute

func (i *Inbound) startRuntimeStatsMonitor(backend *ECommon.Backend) {
	if i.statsCancel != nil {
		return
	}
	ctx, cancel := context.WithCancel(i.ctx)
	done := make(chan struct{})
	i.statsCancel = cancel
	i.statsDone = done
	go i.monitorRuntimeStats(ctx, done, backend)
}

func (i *Inbound) stopRuntimeStatsMonitor() {
	if i.statsCancel == nil {
		return
	}
	i.statsCancel()
	<-i.statsDone
	i.statsCancel = nil
	i.statsDone = nil
}

func (i *Inbound) monitorRuntimeStats(ctx context.Context, done chan<- struct{}, backend *ECommon.Backend) {
	defer close(done)
	ticker := time.NewTicker(runtimeStatsInterval)
	defer ticker.Stop()
	var lastStats ECommon.RuntimeStats
	var tcpWarningLevel int
	var udpWarningLevel int
	for {
		select {
		case <-ctx.Done():
			stats, err := backend.RuntimeStats()
			if err == nil {
				i.logRuntimeStats("final", stats, false)
			}
			return
		case <-ticker.C:
			stats, err := backend.RuntimeStats()
			if err != nil || stats == lastStats {
				continue
			}
			tcpLevel := redirectMapWarningLevel(stats.TCPRedirectEntries, ECommon.TCPRedirectMapCapacity)
			udpLevel := redirectMapWarningLevel(stats.UDPRedirectEntries, ECommon.UDPRedirectMapCapacity)
			shouldWarn := stats.RedirectDrops > lastStats.RedirectDrops ||
				stats.LookupMisses > lastStats.LookupMisses ||
				tcpLevel > tcpWarningLevel || udpLevel > udpWarningLevel
			i.logRuntimeStats("periodic", stats, shouldWarn)
			lastStats = stats
			if tcpLevel > tcpWarningLevel {
				tcpWarningLevel = tcpLevel
			}
			if udpLevel > udpWarningLevel {
				udpWarningLevel = udpLevel
			}
		}
	}
}

func redirectMapWarningLevel(entries uint64, capacity uint64) int {
	percentage := entries * 100 / capacity
	switch {
	case percentage >= 100:
		return 100
	case percentage >= 90:
		return 90
	case percentage >= 75:
		return 75
	default:
		return 0
	}
}

func (i *Inbound) logRuntimeStats(reason string, stats ECommon.RuntimeStats, warning bool) {
	logArgs := []any{
		"eBPF runtime metrics: reason=", reason,
		", redirect_map={tcp_entries:", stats.TCPRedirectEntries,
		", tcp_capacity:", ECommon.TCPRedirectMapCapacity,
		", udp_entries:", stats.UDPRedirectEntries,
		", udp_capacity:", ECommon.UDPRedirectMapCapacity,
		", token_collisions:", stats.TokenCollisions,
		", update_failures:", stats.MapUpdateFailures,
		", drops:", stats.RedirectDrops,
		"}, lookup_misses=", stats.LookupMisses,
	}
	if warning {
		i.logger.Warn(logArgs...)
	} else if reason == "final" {
		i.logger.Info(logArgs...)
	} else {
		i.logger.Debug(logArgs...)
	}
}
