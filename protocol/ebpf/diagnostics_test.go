//go:build with_ebpf && (linux || android)

package ebpf

import "testing"

func TestEBPFDiagnosticSnapshot(t *testing.T) {
	var diagnostics eBPFDiagnostics
	diagnostics.localTCPRedirectMiss.Add(2)
	diagnostics.localUDPBindingMiss.Add(1)
	diagnostics.localUDPRedirectRecovery.Add(5)
	diagnostics.localUDPConnectedRecovery.Add(6)
	diagnostics.sharedUDPLookupError.Add(3)
	diagnostics.sharedFlowReleaseError.Add(4)
	snapshot := diagnostics.snapshot()
	if snapshot.Local.TCPRedirectMiss != 2 || snapshot.Local.UDPBindingMiss != 1 ||
		snapshot.Local.UDPRedirectRecovery != 5 ||
		snapshot.Local.UDPConnectedRecovery != 6 ||
		snapshot.Shared.UDPLookupError != 3 || snapshot.Shared.CleanupError != 4 {
		t.Fatalf("unexpected diagnostic snapshot: %+v", snapshot)
	}
	if snapshot.empty() || snapshot.Local.total() != 14 || snapshot.Shared.total() != 7 {
		t.Fatalf("unexpected diagnostic totals: %+v", snapshot)
	}
}

func TestEmptyEBPFDiagnosticSnapshot(t *testing.T) {
	if !(new(eBPFDiagnostics).snapshot().empty()) {
		t.Fatal("new diagnostic snapshot is not empty")
	}
}
