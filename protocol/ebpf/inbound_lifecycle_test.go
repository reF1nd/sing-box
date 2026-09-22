//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"net/netip"
	"strings"
	"testing"

	E "github.com/sagernet/sing/common/exceptions"

	commonEBPF "github.com/CHIZI-0618/sing-ebpf"
)

func TestNeedsLPMPolicyUsesCompiledEntries(t *testing.T) {
	inbound := &Inbound{
		localEnabled:   true,
		localDataPlane: localDataPlaneCgroup,
		localPolicy: localUIDPolicy{
			IncludeUIDConfigured: true,
		},
	}
	if inbound.needsLPMPolicy() {
		t.Fatal("an explicitly empty UID include policy does not update an LPM trie")
	}

	inbound.localPolicy.IncludeUID = []uidRange{{Start: 1000, End: 1000}}
	if !inbound.needsLPMPolicy() {
		t.Fatal("a compiled UID entry requires an LPM trie update")
	}

	inbound.localEnabled = false
	inbound.localPolicy = localUIDPolicy{}
	inbound.sharedEnabled = true
	inbound.sharedDataPlane = sharedDataPlanePacketRewrite
	inbound.sharedOptions.IncludeSourceCIDR = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	if !inbound.needsLPMPolicy() {
		t.Fatal("a shared source CIDR requires an LPM trie update")
	}
}

type retryProcessTrackerOwner struct {
	closed   bool
	attempts int
}

func (t *retryProcessTrackerOwner) LookupOwner(uint64) (commonEBPF.ProcessSocketOwner, error) {
	return commonEBPF.ProcessSocketOwner{}, nil
}

func (t *retryProcessTrackerOwner) ReleaseCleanup() bool { return false }
func (t *retryProcessTrackerOwner) IsClosed() bool       { return t.closed }
func (t *retryProcessTrackerOwner) Close() error {
	t.attempts++
	if t.attempts == 1 {
		return errors.New("injected process tracker close failure")
	}
	t.closed = true
	return nil
}

func TestCloseProcessTrackerOwnerRetainsFailedCleanup(t *testing.T) {
	tracker := &retryProcessTrackerOwner{}
	retained, err := closeProcessTrackerOwner(tracker)
	if err == nil {
		t.Fatal("expected injected process tracker close failure")
	}
	if retained != tracker {
		t.Fatal("process tracker owner was discarded after a failed close")
	}
	retained, err = closeProcessTrackerOwner(retained)
	if err != nil {
		t.Fatalf("retry process tracker close: %v", err)
	}
	if retained != nil || !tracker.closed {
		t.Fatal("process tracker owner remained retained after cleanup succeeded")
	}
}

// installReclaimCgroupBackendState replaces the reclaim decision for one test
// and records what it was asked about.
func installReclaimCgroupBackendState(
	t *testing.T,
	reclaimed bool,
	err error,
) *[]cgroupBackendCloser {
	t.Helper()
	var asked []cgroupBackendCloser
	previous := reclaimCgroupBackendState
	reclaimCgroupBackendState = func(backend cgroupBackendCloser) (bool, error) {
		asked = append(asked, backend)
		return reclaimed, err
	}
	t.Cleanup(func() { reclaimCgroupBackendState = previous })
	return &asked
}

func TestReclaimCgroupBackendWithoutRetained(t *testing.T) {
	inbound := &Inbound{}
	asked := installReclaimCgroupBackendState(t, true, nil)

	if err := inbound.reclaimCgroupBackend(); err != nil {
		t.Fatalf("reclaim with nothing retained: %v", err)
	}
	if len(*asked) != 0 {
		t.Fatalf("the reclaim ran %d times with nothing retained", len(*asked))
	}
	if inbound.cgroupBackendInstance() != nil {
		t.Fatal("a backend appeared from nowhere")
	}
}

func TestReclaimCgroupBackendReleasesRetained(t *testing.T) {
	retained := &commonEBPF.CgroupBackend{}
	inbound := &Inbound{}
	inbound.setCgroupBackend(retained)
	asked := installReclaimCgroupBackendState(t, true, nil)

	if err := inbound.reclaimCgroupBackend(); err != nil {
		t.Fatalf("reclaim a closable backend: %v", err)
	}
	if len(*asked) != 1 || (*asked)[0] != cgroupBackendCloser(retained) {
		t.Fatalf("the reclaim was asked about %v, want the retained backend", *asked)
	}
	if instance := inbound.cgroupBackendInstance(); instance != nil {
		t.Fatalf("the reclaimed backend is still owned: %p", instance)
	}
}

// TestReclaimCgroupBackendKeepsRetainedWhenCloseFails is the case the retained
// state exists for: the close still cannot finish, so the same instance has to
// stay owned rather than be dropped, and the error has to say so.
func TestReclaimCgroupBackendKeepsRetainedWhenCloseFails(t *testing.T) {
	retained := &commonEBPF.CgroupBackend{}
	inbound := &Inbound{}
	inbound.setCgroupBackend(retained)
	reclaimErr := E.New("still attached")
	installReclaimCgroupBackendState(t, false, reclaimErr)

	err := inbound.reclaimCgroupBackend()
	if err == nil {
		t.Fatal("a reclaim that did not finish reported success")
	}
	if !strings.Contains(err.Error(), "still attached") {
		t.Fatalf("error = %v, want the reclaim failure", err)
	}
	if instance := inbound.cgroupBackendInstance(); instance != retained {
		t.Fatalf("owned backend = %p, want the same instance back (%p)", instance, retained)
	}
}

// TestPrepareCgroupBackendStopsWhenReclaimFails covers the wiring: a reclaim
// that did not finish stops the preparation, so nothing is built over the top of
// a backend that is still attached.
//
// The inbound carries no usable cgroup configuration, so reaching PrepareCgroup
// would fail with its own distinct error. Seeing the reclaim error instead is
// what shows the preparation returned before then.
func TestPrepareCgroupBackendStopsWhenReclaimFails(t *testing.T) {
	retained := &commonEBPF.CgroupBackend{}
	inbound := &Inbound{}
	inbound.setCgroupBackend(retained)
	installReclaimCgroupBackendState(t, false, E.New("still attached"))

	err := inbound.prepareCgroupBackend()
	if err == nil {
		t.Fatal("preparation continued over a backend that is still attached")
	}
	if !strings.Contains(err.Error(), "still attached") {
		t.Fatalf("error = %v, want the reclaim failure rather than a preparation failure", err)
	}
	if instance := inbound.cgroupBackendInstance(); instance != retained {
		t.Fatalf("owned backend = %p, want the retained instance kept (%p)", instance, retained)
	}
}

// TestReclaimCgroupBackendStateReleasesClosedBackend exercises the real decision
// rather than the substituted one, for the case a real backend can reach: one
// that is already closed reclaims without complaint.
func TestReclaimCgroupBackendStateReleasesClosedBackend(t *testing.T) {
	backend := &commonEBPF.CgroupBackend{}
	if !backend.IsClosed() {
		t.Fatal("a zero-value backend does not report itself closed")
	}
	reclaimed, err := reclaimCgroupBackendState(backend)
	if err != nil {
		t.Fatalf("reclaim an already closed backend: %v", err)
	}
	if !reclaimed {
		t.Fatal("an already closed backend was not reported as reclaimed")
	}
}

type retryTestTCRuntime struct {
	closed   bool
	attempts int
}

func (r *retryTestTCRuntime) Backend() *commonEBPF.TCBackend { return nil }
func (r *retryTestTCRuntime) NetworkInfo() commonEBPF.TCNetworkInfo {
	return commonEBPF.TCNetworkInfo{}
}

func (r *retryTestTCRuntime) TCDiagnostics() commonEBPF.TCDiagnostics {
	return commonEBPF.TCDiagnostics{}
}
func (r *retryTestTCRuntime) Reconcile(string, []string, []netip.Addr) error { return nil }
func (r *retryTestTCRuntime) HealthCheck(string, []string, []netip.Addr) (bool, error) {
	return true, nil
}
func (r *retryTestTCRuntime) RepairInfrastructure() (bool, error) { return false, nil }
func (r *retryTestTCRuntime) AttachmentStateChanged(string, []string) (bool, error) {
	return false, nil
}
func (r *retryTestTCRuntime) AttachmentDescriptions() []string { return nil }
func (r *retryTestTCRuntime) AttachmentDiagnostics() []commonEBPF.AttachmentInfo {
	return nil
}
func (r *retryTestTCRuntime) UpdateHostAddresses([]netip.Addr) error { return nil }
func (r *retryTestTCRuntime) Disable() error                         { return nil }
func (r *retryTestTCRuntime) IsClosed() bool                         { return r.closed }
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
