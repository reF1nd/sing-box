//go:build with_ebpf && (linux || android) && !cgo

package ebpf

import (
	"net/netip"
	"runtime"

	E "github.com/sagernet/sing/common/exceptions"
)

const SharedNetworkMapCapacity = 65536

type SharedNetworkBackend struct{}

func PrepareSharedNetwork(
	*Backend,
	uint16,
	bool,
	bool,
	netip.Prefix,
	netip.Prefix,
) (*SharedNetworkBackend, error) {
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
func (b *SharedNetworkBackend) DeleteRedirect(uint8, netip.AddrPort, netip.AddrPort) error {
	return unsupportedSharedNetworkError()
}
func (b *SharedNetworkBackend) UpdateHostAddresses([]netip.Addr) error {
	return unsupportedSharedNetworkError()
}
func (b *SharedNetworkBackend) Close() error   { return nil }
func (b *SharedNetworkBackend) IsClosed() bool { return true }
