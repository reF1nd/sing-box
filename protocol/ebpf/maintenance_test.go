//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"testing"
	"time"

	commonEBPF "github.com/CHIZI-0618/sing-ebpf"
)

func TestTCMaintenanceCoalescesEventsAndContinuesPartialScans(t *testing.T) {
	now := time.Unix(1, 0)
	schedule := maintenanceSchedule{config: dataPlaneMaintenanceSchedule}
	if schedule.delay(now) != 0 || schedule.finish(now, true, false, nil) != 0 {
		t.Fatal("normal completed sweep should wait for activity or watchdog")
	}
	for n := 1; n < 50; n++ {
		elapsed := time.Duration(n) * 100 * time.Millisecond
		if got := schedule.delay(now.Add(elapsed)); got != dataPlaneMaintenanceSchedule.cooldown-elapsed {
			t.Fatalf("wake %d postponed deadline: %v", n, got)
		}
	}
	now = now.Add(dataPlaneMaintenanceSchedule.cooldown)
	if schedule.delay(now) != 0 {
		t.Fatal("pending event was not released")
	}
	if got := schedule.finish(now, false, false, nil); got != dataPlaneMaintenanceSchedule.continuation {
		t.Fatalf("partial scan delay = %v", got)
	}
	if got := schedule.finish(now, true, true, nil); got != dataPlaneMaintenanceSchedule.pressure {
		t.Fatalf("pressure delay = %v", got)
	}
	if schedule.finish(now, false, true, errors.New("scan failed")) != dataPlaneMaintenanceSchedule.cooldown || schedule.delay(now) != dataPlaneMaintenanceSchedule.cooldown {
		t.Fatal("scan failure must not cause a short-delay retry loop")
	}
	if schedule.finish(now, false, true, errors.New("scan failed")) != 2*dataPlaneMaintenanceSchedule.cooldown {
		t.Fatal("repeated failure must back off")
	}
}

func TestMaintenanceJobKeepsExistingDeadline(t *testing.T) {
	now := time.Now()
	job := newMaintenanceJob(dataPlaneMaintenanceSchedule)
	job.schedule.next = now.Add(time.Second)
	if job.ready(now) {
		t.Fatal("maintenance job ran before its deadline")
	}
	timer := job.timer
	if timer == nil || job.continuation == nil {
		t.Fatal("maintenance job did not arm its continuation")
	}
	if job.ready(now.Add(100*time.Millisecond)) || job.timer != timer {
		t.Fatal("repeated wake replaced the active maintenance deadline")
	}
	job.stop()
}

func TestTCAssignmentPressureHysteresis(t *testing.T) {
	usage := commonEBPF.MapUsage{Entries: 70, Capacity: 100}
	active, rounds, entered, exited := updateTCAssignmentPressure(false, 0, usage)
	if !active || rounds != 0 || !entered || exited {
		t.Fatalf("pressure did not enter: active=%v rounds=%d entered=%v exited=%v", active, rounds, entered, exited)
	}
	usage.Entries = 50
	for round := uint32(1); round <= tcAssignmentPressureExitRounds; round++ {
		active, rounds, entered, exited = updateTCAssignmentPressure(active, rounds, usage)
		if round < tcAssignmentPressureExitRounds && (!active || rounds != round || entered || exited) {
			t.Fatalf("pressure exited too early at round %d: active=%v rounds=%d entered=%v exited=%v", round, active, rounds, entered, exited)
		}
	}
	if active || rounds != 0 || entered || !exited {
		t.Fatalf("pressure did not clear: active=%v rounds=%d entered=%v exited=%v", active, rounds, entered, exited)
	}
}

func TestTCAssignmentPartialUsageIsNotPressureEvidence(t *testing.T) {
	active, rounds, entered, exited := updateTCAssignmentPressure(false, 0, commonEBPF.MapUsage{})
	if active || rounds != 0 || entered || exited {
		t.Fatalf("empty/unknown usage changed pressure state: active=%v rounds=%d entered=%v exited=%v", active, rounds, entered, exited)
	}
}
func TestTCSweepReportsIndependentMapValidity(t *testing.T) {
	i := &Inbound{}
	i.recordTCAssignmentSweep(commonEBPF.TCFlowSweepResult{
		Usage: commonEBPF.MapUsage{Entries: 7, Capacity: 64}, UsageKnown: true,
		ReturnUsage: commonEBPF.MapUsage{Entries: 40, Capacity: 64}, ReturnUsageKnown: true, Complete: true,
	})
	i.recordTCAssignmentSweep(commonEBPF.TCFlowSweepResult{
		Usage: commonEBPF.MapUsage{Entries: 8, Capacity: 64}, UsageKnown: true,
		FailureMap: "sb_tc_return", Failure: "scan",
	})
	if !i.tcAssignmentSweepUsageKnown.Load() || i.tcReturnSweepUsageKnown.Load() {
		t.Fatal("return failure erased assignment validity or reported stale return usage as current")
	}
	if i.tcAssignmentSweepEntries.Load() != 8 || i.tcReturnSweepEntries.Load() != 40 {
		t.Fatal("per-map snapshots were mixed")
	}
	if name, _ := i.tcAssignmentSweepFailureMap.Load().(string); name != "sb_tc_return" {
		t.Fatalf("failure map = %q", name)
	}
}
