//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"time"

	commonEBPF "github.com/CHIZI-0618/sing-ebpf"
)

const (
	tcAssignmentPressureMaxIdle      = 15 * time.Second
	tcAssignmentNormalMaxIdle        = 2 * time.Minute
	tcAssignmentMaintenanceBudget    = 1024
	tcAssignmentPressureEnterPercent = 70
	tcAssignmentPressureExitPercent  = 50
	tcAssignmentPressureExitRounds   = 3
)

func (i *Inbound) maintainTCAssignments(job *maintenanceJob) {
	if delay := job.schedule.delay(time.Now()); delay > 0 {
		job.reset(delay)
		return
	}
	complete, err := i.sweepTCAssignmentMaintenance()
	job.finish(time.Now(), complete, i.tcAssignmentSweepPressure.Load(), err)
}

// startTCAssignmentJanitor owns the TC assignment side of the same bounded
// maintenance model used by shared packet-rewrite. It is event-woken for
// observed assignment activity, periodically checks pressure for kernel-only
// updates, and immediately continues a partial fallback traversal.
func (i *Inbound) startTCAssignmentJanitor() {
	i.tcAssignmentJanitorAccess.Lock()
	defer i.tcAssignmentJanitorAccess.Unlock()
	if i.tcAssignmentJanitorCancel != nil || i.tcBackend() == nil {
		return
	}
	ctx, cancel := context.WithCancel(i.ctx)
	done := make(chan struct{})
	i.tcAssignmentJanitorCancel = cancel
	i.tcAssignmentJanitorDone = done
	go i.runTCAssignmentJanitor(ctx, done)
}

func (i *Inbound) stopTCAssignmentJanitor() {
	i.tcAssignmentJanitorAccess.Lock()
	if i.tcAssignmentJanitorCancel == nil {
		i.tcAssignmentJanitorAccess.Unlock()
		return
	}
	cancel := i.tcAssignmentJanitorCancel
	done := i.tcAssignmentJanitorDone
	i.tcAssignmentJanitorCancel = nil
	i.tcAssignmentJanitorDone = nil
	i.tcAssignmentJanitorAccess.Unlock()
	cancel()
	<-done
}

func (i *Inbound) requestTCAssignmentMaintenance() {
	if i.tcAssignmentWake == nil {
		return
	}
	select {
	case i.tcAssignmentWake <- struct{}{}:
	default:
	}
}

func (i *Inbound) runTCAssignmentJanitor(ctx context.Context, done chan<- struct{}) {
	defer close(done)
	ticker := time.NewTicker(tcAssignmentMaintenanceSchedule.watchdog)
	defer ticker.Stop()
	job := newMaintenanceJob(tcAssignmentMaintenanceSchedule)
	for {
		// Leave one wake queued during a cooldown/continuation instead of
		// waking this goroutine and resetting its timer for every UDP packet.
		var wake <-chan struct{}
		if job.continuation == nil {
			wake = i.tcAssignmentWake
		}
		select {
		case <-ctx.Done():
			job.stop()
			return
		case <-wake:
		case <-ticker.C:
		case <-job.continuation:
			job.continuation = nil
		}
		i.maintainTCAssignments(&job)
	}
}

// sweepTCAssignmentMaintenance is shared by the standalone TC janitor and the
// shared packet-rewrite maintenance worker. It keeps pressure hysteresis in
// the inbound so both paths expose identical state and cleanup behavior.
func (i *Inbound) sweepTCAssignmentMaintenance() (bool, error) {
	backend := i.tcBackend()
	if backend == nil || backend.IsClosed() {
		return true, nil
	}
	maxIdle := tcAssignmentNormalMaxIdle
	if i.tcAssignmentSweepPressure.Load() {
		maxIdle = tcAssignmentPressureMaxIdle
	}
	result, err := backend.SweepFlows(maxIdle, tcAssignmentMaintenanceBudget)
	i.recordTCAssignmentSweep(result)
	if err != nil {
		i.interfaceWarnings.reconcile.warn(i.logger, "sweep TC eBPF assignments: ", err)
		return true, err
	}
	if !result.Complete || !result.UsageKnown || !result.ReturnUsageKnown {
		return false, nil
	}
	// Both maps share the worker, but a nearly-full return map must not be
	// hidden behind a mostly-empty assignment map after TCP accepts.
	pressureUsage := result.Usage
	if result.ReturnUsageKnown && uint64(result.ReturnUsage.Entries)*uint64(pressureUsage.Capacity) > uint64(pressureUsage.Entries)*uint64(result.ReturnUsage.Capacity) {
		pressureUsage = result.ReturnUsage
	}
	active, rounds, entered, exited := updateTCAssignmentPressure(
		i.tcAssignmentSweepPressure.Load(),
		i.tcAssignmentPressureRounds.Load(),
		pressureUsage,
	)
	i.tcAssignmentSweepPressure.Store(active)
	i.tcAssignmentPressureRounds.Store(rounds)
	if entered {
		i.logger.Warn("eBPF ", ebpfStructuredEvent("tc_map_pressure", map[string]any{
			"entries":  pressureUsage.Entries,
			"capacity": pressureUsage.Capacity,
			"max_idle": tcAssignmentPressureMaxIdle.String(),
		}))
	} else if exited {
		i.logger.Info("eBPF ", ebpfStructuredEvent("tc_map_pressure_cleared", map[string]any{
			"entries":  pressureUsage.Entries,
			"capacity": pressureUsage.Capacity,
		}))
	}
	return true, nil
}

func updateTCAssignmentPressure(active bool, belowExitRounds uint32, usage commonEBPF.MapUsage) (bool, uint32, bool, bool) {
	return updateMapPressure(active, belowExitRounds, usage, mapPressureHysteresis{
		enterPercent: tcAssignmentPressureEnterPercent,
		exitPercent:  tcAssignmentPressureExitPercent,
		exitRounds:   tcAssignmentPressureExitRounds,
	})
}

func (i *Inbound) recordTCAssignmentSweep(result commonEBPF.TCFlowSweepResult) {
	i.tcReturnSweepScanned.Add(uint64(result.ReturnScanned))
	i.tcReturnSweepRemoved.Add(uint64(result.ReturnRemoved))
	i.tcAssignmentSweepUsageKnown.Store(result.UsageKnown)
	i.tcReturnSweepUsageKnown.Store(result.ReturnUsageKnown)
	i.tcAssignmentSweepFailureMap.Store(result.FailureMap)
	if result.UsageKnown {
		i.tcAssignmentSweepEntries.Store(uint64(result.Usage.Entries))
		i.tcAssignmentSweepCapacity.Store(uint64(result.Usage.Capacity))
	}
	if result.ReturnUsageKnown {
		i.tcReturnSweepEntries.Store(uint64(result.ReturnUsage.Entries))
		i.tcReturnSweepCapacity.Store(uint64(result.ReturnUsage.Capacity))
	}
	i.tcAssignmentSweepScanned.Add(uint64(result.Scanned))
	i.tcAssignmentSweepRemoved.Add(uint64(result.Removed))
	i.tcAssignmentSweepMissing.Add(uint64(result.Missing))
	i.tcAssignmentSweepSuperseded.Add(uint64(result.Superseded))
	i.tcAssignmentSweepInFlight.Add(uint64(result.InFlight))
	i.tcAssignmentSweepRuns.Add(1)
	i.tcAssignmentSweepFailure.Store(result.Failure)
	i.tcAssignmentSweepComplete.Store(result.Complete)
	i.tcAssignmentSweepLastAt.Store(time.Now().UnixNano())
	if result.Complete && result.Failure == "" {
		i.tcAssignmentSweepPartialAt.Store(0)
	} else {
		i.tcAssignmentSweepPartial.Add(1)
		if i.tcAssignmentSweepPartialAt.Load() == 0 {
			i.tcAssignmentSweepPartialAt.Store(time.Now().UnixNano())
		}
	}
}
