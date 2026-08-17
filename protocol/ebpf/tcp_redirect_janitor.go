//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"time"
)

const (
	localTCPRedirectMaxAge        = 10 * time.Minute
	localTCPRedirectSweepInterval = time.Minute
	localTCPRedirectScanInterval  = 5 * time.Second
	localTCPRedirectScanBudget    = 1024
)

func (i *Inbound) startTCPRedirectJanitor() {
	if i.tcpJanitorStop != nil {
		return
	}
	ctx, cancel := context.WithCancel(i.ctx)
	done := make(chan struct{})
	i.tcpJanitorStop = cancel
	i.tcpJanitorDone = done
	go i.runTCPRedirectJanitor(ctx, done)
}

func (i *Inbound) stopTCPRedirectJanitor() {
	if i.tcpJanitorStop == nil {
		return
	}
	i.tcpJanitorStop()
	<-i.tcpJanitorDone
	i.tcpJanitorStop = nil
	i.tcpJanitorDone = nil
}

func (i *Inbound) runTCPRedirectJanitor(ctx context.Context, done chan<- struct{}) {
	defer close(done)
	timer := time.NewTimer(localTCPRedirectSweepInterval)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		nextInterval := localTCPRedirectSweepInterval
		backend := i.cgroupBackendInstance()
		if backend == nil {
			return
		}
		started := time.Now()
		result, err := backend.SweepStaleTCPRedirects(localTCPRedirectMaxAge, localTCPRedirectScanBudget)
		i.debug.observe(ebpfDebugTaskLocalTCPRedirectSweep, time.Since(started), err)
		if err != nil {
			i.tcpJanitorWarn.warn(i.logger, "sweep stale local TCP redirects: ", err)
			timer.Reset(nextInterval)
			continue
		}
		if !result.Complete {
			nextInterval = localTCPRedirectScanInterval
		}
		if result.Removed > 0 {
			if result.Complete {
				i.logger.Debug(
					"eBPF local TCP redirect cleanup: removed=", result.Removed,
					", redirect_state=", result.Usage.Entries, "/", result.Usage.Capacity,
				)
			} else {
				i.logger.Debug(
					"eBPF local TCP redirect cleanup: removed=", result.Removed,
					", scanned=", result.Scanned,
					", scan_complete=false",
				)
			}
		}
		timer.Reset(nextInterval)
	}
}
