//go:build with_ebpf && ebpf_debug && (linux || android)

package ebpf

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestEBPFDebugStateSnapshot(t *testing.T) {
	var state eBPFDebugState
	state.observe(ebpfDebugTaskSharedFlowSweep, 5*time.Millisecond, nil)
	state.observe(ebpfDebugTaskSharedFlowSweep, 9*time.Millisecond, errors.New("test"))
	snapshot := state.snapshot()
	metric := snapshot.Maintenance[ebpfDebugTaskSharedFlowSweep]
	if !snapshot.Build || metric.Runs != 2 || metric.Errors != 1 ||
		metric.TotalDurationNanos != uint64(14*time.Millisecond) ||
		metric.MaxDurationNanos != uint64(9*time.Millisecond) ||
		metric.LastDurationNanos != uint64(9*time.Millisecond) {
		t.Fatalf("unexpected eBPF debug snapshot: %+v", snapshot)
	}
	if snapshot.GoRuntime.Goroutines == 0 || snapshot.GoRuntime.SysBytes == 0 {
		t.Fatalf("incomplete Go runtime snapshot: %+v", snapshot.GoRuntime)
	}
	var localWriter eBPFDebugUDPWriterState
	if !state.localUDPBindingMiss.observe(&localWriter, false) ||
		state.localUDPBindingMiss.observe(&localWriter, false) {
		t.Fatal("unexpected local UDP binding miss session classification")
	}
	var sharedWriter eBPFDebugUDPWriterState
	if !state.sharedUDPBindingMiss.observe(&sharedWriter, true) {
		t.Fatal("unexpected shared UDP binding miss session classification")
	}
	snapshot = state.snapshot()
	if snapshot.UDPBindingMiss.Local.UnconnectedPackets != 2 ||
		snapshot.UDPBindingMiss.Local.UnconnectedSessions != 1 ||
		snapshot.UDPBindingMiss.Shared.ConnectedPackets != 1 ||
		snapshot.UDPBindingMiss.Shared.ConnectedSessions != 1 {
		t.Fatalf("unexpected UDP binding miss snapshot: %+v", snapshot.UDPBindingMiss)
	}
}

func TestEBPFDebugPProfMux(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/debug/pprof/goroutine?debug=1", nil)
	response := httptest.NewRecorder()
	newEBPFDebugPProfMux().ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Body.Len() == 0 {
		t.Fatalf("unexpected pprof response: status=%d length=%d", response.Code, response.Body.Len())
	}
}

func TestEBPFDebugPProfRejectsInvalidPort(t *testing.T) {
	t.Setenv(ebpfDebugPProfPortEnv, "invalid")
	if release, err := acquireEBPFDebugPProf(nil); err == nil || release != nil {
		t.Fatalf("unexpected pprof result: release=%v err=%v", release != nil, err)
	}
}
