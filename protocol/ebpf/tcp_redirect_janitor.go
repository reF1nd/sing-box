//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"time"
)

const (
	localTCPRedirectMaxAge        = 10 * time.Minute
	localTCPRedirectSweepInterval = 5 * time.Minute
	localTCPRedirectPollInterval  = 30 * time.Second
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
	i.maintenanceAccess.Lock()
	i.tcpJanitorWake = make(chan struct{}, 1)
	i.maintenanceAccess.Unlock()
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
	i.maintenanceAccess.Lock()
	i.tcpJanitorWake = nil
	i.maintenanceAccess.Unlock()
}

func (i *Inbound) wakeTCPRedirectJanitor() {
	i.maintenanceAccess.RLock()
	wake := i.tcpJanitorWake
	i.maintenanceAccess.RUnlock()
	if wake == nil {
		return
	}
	select {
	case wake <- struct{}{}:
	default:
	}
}

func (i *Inbound) runTCPRedirectJanitor(ctx context.Context, done chan<- struct{}) {
	defer close(done)
	timer := time.NewTimer(localTCPRedirectSweepInterval)
	defer timer.Stop()
	pollTicker := time.NewTicker(localTCPRedirectPollInterval)
	defer pollTicker.Stop()
	var lastReservationFailures uint64
	resetTimer := func(interval time.Duration) {
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(interval)
	}
	for {
		runSweep := false
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			runSweep = true
		case <-i.tcpJanitorWake:
			runSweep = true
		case <-pollTicker.C:
			backend := i.cgroupBackendInstance()
			if backend == nil {
				return
			}
			failures, err := backend.TCPRedirectReservationFailures()
			if err != nil {
				i.tcpJanitorWarn.warn(i.logger, "read local TCP redirect reservation failures: ", err)
				continue
			}
			runSweep = failures > lastReservationFailures
			lastReservationFailures = failures
		}
		if !runSweep {
			continue
		}
		nextInterval := localTCPRedirectSweepInterval
		backend := i.cgroupBackendInstance()
		if backend == nil {
			return
		}
		result, err := backend.SweepStaleTCPRedirects(localTCPRedirectMaxAge, localTCPRedirectScanBudget)
		if err != nil {
			i.tcpJanitorWarn.warn(i.logger, "sweep stale local TCP redirects: ", err)
			resetTimer(nextInterval)
			continue
		}
		if !result.Complete {
			nextInterval = localTCPRedirectScanInterval
		}
		i.logDebugLocalTCPCleanup(result)
		resetTimer(nextInterval)
	}
}
