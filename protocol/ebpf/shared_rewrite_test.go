//go:build with_ebpf && (linux || android)

package ebpf

import (
	"testing"

	commonEBPF "github.com/sagernet/sing-box/common/ebpf"
)

func TestUpdateSharedRewriteFlowPressure(t *testing.T) {
	usage := commonEBPF.MapUsage{Capacity: 100}
	active, rounds, entered, exited := updateSharedFlowPressure(false, 0, usage)
	if active || rounds != 0 || entered || exited {
		t.Fatal("empty map unexpectedly entered pressure mode")
	}
	usage.Entries = 70
	active, rounds, entered, exited = updateSharedFlowPressure(active, rounds, usage)
	if !active || !entered || exited {
		t.Fatal("70% map usage did not enter pressure mode")
	}
	usage.Entries = 50
	for expected := 1; expected < sharedFlowPressureExitRounds; expected++ {
		active, rounds, entered, exited = updateSharedFlowPressure(active, rounds, usage)
		if !active || rounds != expected || entered || exited {
			t.Fatalf("unexpected pressure exit state at round %d", expected)
		}
	}
	active, rounds, entered, exited = updateSharedFlowPressure(active, rounds, usage)
	if active || rounds != 0 || entered || !exited {
		t.Fatal("pressure mode did not exit after stable low usage")
	}
}

func TestFlowUsagePressure(t *testing.T) {
	usage := commonEBPF.MapUsage{Capacity: 100}
	if flowUsagePressure(false, usage) {
		t.Fatal("empty flow usage unexpectedly entered pressure mode")
	}
	usage.Entries = 70
	if !flowUsagePressure(false, usage) {
		t.Fatal("70% flow usage did not enter pressure mode")
	}
	usage.Entries = 50
	if flowUsagePressure(true, usage) {
		t.Fatal("50% flow usage did not reach the pressure exit threshold")
	}
	usage.Entries = 49
	if flowUsagePressure(true, usage) {
		t.Fatal("flow usage pressure did not clear below exit threshold")
	}
}

func TestSharedFlowWakeMaintainsPressureSweeps(t *testing.T) {
	usage := commonEBPF.MapUsage{Entries: 80, Capacity: 100}
	knownPressure, sweepRequested := updateSharedFlowWakeState(true, true, false, usage)
	if !knownPressure || !sweepRequested {
		t.Fatalf("pressure wake did not request a maintenance sweep: known=%v requested=%v", knownPressure, sweepRequested)
	}

	usage.Entries = 40
	knownPressure, sweepRequested = updateSharedFlowWakeState(true, true, false, usage)
	if knownPressure || !sweepRequested {
		t.Fatalf("pressure recovery wake stopped maintenance before exit rounds: known=%v requested=%v", knownPressure, sweepRequested)
	}
}

func TestSharedFlowWakeContinuesIncompleteScan(t *testing.T) {
	usage := commonEBPF.MapUsage{Entries: 0, Capacity: 100}
	knownPressure, sweepRequested := updateSharedFlowWakeState(false, false, true, usage)
	if knownPressure || !sweepRequested {
		t.Fatalf("incomplete scan wake was not scheduled: known=%v requested=%v", knownPressure, sweepRequested)
	}
}
