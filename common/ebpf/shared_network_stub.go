//go:build with_ebpf && (linux || android) && !cgo

package ebpf

import (
	"net/netip"
	"runtime"

	E "github.com/sagernet/sing/common/exceptions"
)

type SharedNetworkBackend struct{}

func PrepareSharedNetwork(*CgroupBackend, SharedNetworkConfig) (*SharedNetworkBackend, error) {
	return nil, unsupportedSharedNetworkError()
}

func unsupportedSharedNetworkError() error {
	return E.New("shared-network eBPF is not supported on ", runtime.GOOS, "/", runtime.GOARCH, " in this build")
}

func (b *SharedNetworkBackend) Enable() error  { return unsupportedSharedNetworkError() }
func (b *SharedNetworkBackend) Disable() error { return nil }
func (b *SharedNetworkBackend) IngressProgramFD() int {
	return -1
}
func (b *SharedNetworkBackend) EgressProgramFD() int {
	return -1
}
func (b *SharedNetworkBackend) LookupOriginal(uint8, netip.AddrPort, netip.AddrPort) (OriginalDestination, error) {
	return OriginalDestination{}, unsupportedSharedNetworkError()
}
func (b *SharedNetworkBackend) LookupFlow(uint8, netip.AddrPort, netip.AddrPort) (OriginalDestination, *SharedNetworkFlowHandle, error) {
	return OriginalDestination{}, nil, unsupportedSharedNetworkError()
}
func (b *SharedNetworkBackend) ReleaseFlow(*SharedNetworkFlowHandle) error {
	return unsupportedSharedNetworkError()
}
func (b *SharedNetworkBackend) UpdateHostAddresses([]netip.Addr) error {
	return unsupportedSharedNetworkError()
}
func (b *SharedNetworkBackend) UpdateBypassCIDR([]netip.Prefix) (bool, error) {
	return false, unsupportedSharedNetworkError()
}
func (b *SharedNetworkBackend) SetBypassCIDRState([]netip.Prefix) error {
	return unsupportedSharedNetworkError()
}
func (b *SharedNetworkBackend) BypassCIDRCount() (int, int) { return 0, 0 }
func (b *SharedNetworkBackend) Close() error                { return nil }
func (b *SharedNetworkBackend) IsClosed() bool              { return true }
