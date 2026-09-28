//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net/netip"

	commonEBPF "github.com/CHIZI-0618/sing-ebpf"
)

type testTCRuntime struct {
	backend     *commonEBPF.TCBackend
	networkInfo commonEBPF.TCNetworkInfo
	attachments []commonEBPF.AttachmentInfo
	closed      bool
}

func (r *testTCRuntime) Backend() *commonEBPF.TCBackend        { return r.backend }
func (r *testTCRuntime) NetworkInfo() commonEBPF.TCNetworkInfo { return r.networkInfo }
func (r *testTCRuntime) TCDiagnostics() commonEBPF.TCDiagnostics {
	return commonEBPF.TCDiagnostics{NetworkInfo: r.networkInfo}
}
func (r *testTCRuntime) Reconcile(string, []string, []netip.Addr) error { return nil }
func (r *testTCRuntime) HealthCheck(string, []string, []netip.Addr) (bool, error) {
	return true, nil
}
func (r *testTCRuntime) RepairInfrastructure() (bool, error)                   { return false, nil }
func (r *testTCRuntime) AttachmentStateChanged(string, []string) (bool, error) { return false, nil }
func (r *testTCRuntime) AttachmentDescriptions() []string {
	descriptions := make([]string, 0, len(r.attachments))
	for _, attachment := range r.attachments {
		descriptions = append(descriptions, attachment.InterfaceName+"("+attachment.Role+","+attachment.Mechanism+")")
	}
	return descriptions
}
func (r *testTCRuntime) AttachmentDiagnostics() []commonEBPF.AttachmentInfo {
	return append([]commonEBPF.AttachmentInfo(nil), r.attachments...)
}
func (r *testTCRuntime) UpdateHostAddresses([]netip.Addr) error { return nil }
func (r *testTCRuntime) Disable() error                         { return nil }
func (r *testTCRuntime) IsClosed() bool                         { return r.closed }
func (r *testTCRuntime) Close() error                           { r.closed = true; return nil }

type testSharedKernelRuntime struct {
	backend     *commonEBPF.SharedPacketRewriteBackend
	attachments []commonEBPF.AttachmentInfo
	enabled     bool
	closed      bool
	rebuild     bool
}

func (r *testSharedKernelRuntime) Backend() *commonEBPF.SharedPacketRewriteBackend { return r.backend }
func (r *testSharedKernelRuntime) Reconcile([]string, []netip.Addr) error          { return nil }
func (r *testSharedKernelRuntime) HealthCheck([]string, []netip.Addr) (bool, error) {
	return true, nil
}
func (r *testSharedKernelRuntime) IsEnabled() bool { return r.enabled }
func (r *testSharedKernelRuntime) AttachmentDescriptions() []string {
	descriptions := make([]string, 0, len(r.attachments))
	for _, attachment := range r.attachments {
		descriptions = append(descriptions, attachment.InterfaceName+"("+attachment.Mechanism+")")
	}
	return descriptions
}
func (r *testSharedKernelRuntime) AttachmentDiagnostics() []commonEBPF.AttachmentInfo {
	return append([]commonEBPF.AttachmentInfo(nil), r.attachments...)
}
func (r *testSharedKernelRuntime) BackendClosed() bool {
	return r.backend == nil || r.backend.IsClosed()
}
func (r *testSharedKernelRuntime) IsClosed() bool        { return r.closed }
func (r *testSharedKernelRuntime) RequiresRebuild() bool { return r.rebuild }
func (r *testSharedKernelRuntime) Close() error          { r.closed = true; return nil }
