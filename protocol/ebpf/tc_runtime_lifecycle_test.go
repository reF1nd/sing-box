//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"net/netip"
	"testing"

	commonEBPF "github.com/CHIZI-0618/sing-ebpf"
)

type retryTestTCRuntime struct {
	closed   bool
	attempts int
}

func (r *retryTestTCRuntime) Backend() *commonEBPF.TCBackend { return nil }
func (r *retryTestTCRuntime) NetworkInfo() commonEBPF.TCNetworkInfo {
	return commonEBPF.TCNetworkInfo{}
}
func (r *retryTestTCRuntime) Reconcile(string, []string, []netip.Addr) error { return nil }
func (r *retryTestTCRuntime) RepairInfrastructure() (bool, error)            { return false, nil }
func (r *retryTestTCRuntime) AttachmentStateChanged(string, []string) (bool, error) {
	return false, nil
}
func (r *retryTestTCRuntime) AttachmentDescriptions() []string                   { return nil }
func (r *retryTestTCRuntime) AttachmentDiagnostics() []commonEBPF.AttachmentInfo { return nil }
func (r *retryTestTCRuntime) UpdateHostAddresses([]netip.Addr) error             { return nil }
func (r *retryTestTCRuntime) Disable() error                                     { return nil }
func (r *retryTestTCRuntime) IsClosed() bool                                     { return r.closed }
func (r *retryTestTCRuntime) Close() error {
	r.attempts++
	if r.attempts == 1 {
		return errors.New("injected runtime close failure")
	}
	r.closed = true
	return nil
}

func TestInboundRetainsTCRuntimeAfterFailedClose(t *testing.T) {
	runtime := &retryTestTCRuntime{}
	inbound := &Inbound{}
	inbound.setTCDataPlane(runtime)
	if err := inbound.closeTCDataPlane(); err == nil {
		t.Fatal("expected injected runtime close failure")
	}
	if inbound.tcDataPlane != runtime {
		t.Fatal("inbound lost runtime needed for cleanup retry")
	}
	if err := inbound.closeTCDataPlane(); err != nil {
		t.Fatalf("retry runtime close: %v", err)
	}
	if inbound.tcDataPlane != nil || !runtime.closed {
		t.Fatal("inbound retained runtime after successful cleanup")
	}
}
