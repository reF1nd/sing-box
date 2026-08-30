//go:build with_ebpf && (linux || android)

package ebpf

// policyVector is the data-plane-independent policy description. Each backend
// encodes the same vector into its own control ABI because the hook contexts
// and map sets are intentionally different.
type policyVector struct {
	EnableTCP           bool
	EnableUDP           bool
	EnableIPv4          bool
	EnableLocalIPv6     bool
	EnableSharedIPv6    bool
	UIDPolicy           bool
	UIDDefaultBypass    bool
	LocalBypassPrivate  bool
	SharedBypassPrivate bool
	LocalBypassPort     bool
	SharedBypassPort    bool
	BypassIPv4          bool
	BypassIPv6          bool
	HostIPv4            bool
	HostIPv6            bool
	IncludeSource       bool
	ExcludeSource       bool
	IncludeSourceMAC    bool
	ExcludeSourceMAC    bool
	BypassFlowCache     bool
	FakeIPIPv4          bool
	FakeIPIPv6          bool
}

func (v policyVector) tcFlags() uint32 {
	var flags uint32
	if v.EnableIPv4 {
		flags |= tcFlagIPv4
	}
	if v.EnableLocalIPv6 {
		flags |= tcFlagLocalIPv6
	}
	if v.EnableSharedIPv6 {
		flags |= tcFlagSharedIPv6
	}
	if v.EnableTCP {
		flags |= tcFlagTCP
	}
	if v.EnableUDP {
		flags |= tcFlagUDP
	}
	if v.UIDPolicy {
		flags |= 1 << 4
	}
	if v.UIDDefaultBypass {
		flags |= 1 << 5
	}
	if v.LocalBypassPrivate {
		flags |= 1 << 6
	}
	if v.SharedBypassPrivate {
		flags |= 1 << 7
	}
	if v.BypassIPv4 {
		flags |= 1 << 8
	}
	if v.BypassIPv6 {
		flags |= 1 << 9
	}
	if v.FakeIPIPv4 {
		flags |= 1 << 10
	}
	if v.FakeIPIPv6 {
		flags |= 1 << 11
	}
	if v.IncludeSource {
		flags |= 1 << 12
	}
	if v.ExcludeSource {
		flags |= 1 << 13
	}
	if v.IncludeSourceMAC {
		flags |= 1 << 14
	}
	if v.ExcludeSourceMAC {
		flags |= 1 << 15
	}
	if v.HostIPv4 {
		flags |= 1 << 16
	}
	if v.HostIPv6 {
		flags |= 1 << 17
	}
	if v.LocalBypassPort {
		flags |= tcFlagLocalBypassPort
	}
	if v.SharedBypassPort {
		flags |= tcFlagSharedBypassPort
	}
	return flags
}

func (v policyVector) cgroupFlags() uint32 {
	var flags uint32
	if v.EnableTCP {
		flags |= cgroupFlagTCP
	}
	if v.EnableUDP {
		flags |= cgroupFlagUDP
	}
	if v.EnableIPv4 {
		flags |= cgroupFlagIPv4
	}
	if v.EnableLocalIPv6 {
		flags |= cgroupFlagIPv6
	}
	if v.UIDPolicy {
		flags |= cgroupFlagUIDPolicy
	}
	if v.UIDDefaultBypass {
		flags |= cgroupFlagUIDDefaultBypass
	}
	if v.BypassIPv4 {
		flags |= cgroupFlagBypassIPv4
	}
	if v.BypassIPv6 {
		flags |= cgroupFlagBypassIPv6
	}
	if v.LocalBypassPrivate {
		flags |= cgroupFlagBypassPrivateAddress
	}
	if v.HostIPv4 {
		flags |= cgroupFlagHostIPv4
	}
	if v.HostIPv6 {
		flags |= cgroupFlagHostIPv6
	}
	if v.FakeIPIPv4 {
		flags |= cgroupFlagFakeIPIPv4
	}
	if v.FakeIPIPv6 {
		flags |= cgroupFlagFakeIPIPv6
	}
	if v.LocalBypassPort {
		flags |= cgroupFlagBypassPort
	}
	if v.EnableUDP {
		flags |= cgroupFlagUDPFlow
	}
	return flags
}

func (v policyVector) sharedFlags() uint32 {
	var flags uint32
	if v.EnableIPv4 {
		flags |= sharedNetworkFlagIPv4
	}
	if v.EnableSharedIPv6 {
		flags |= sharedNetworkFlagIPv6
	}
	if v.EnableTCP {
		flags |= sharedNetworkFlagTCP
	}
	if v.EnableUDP {
		flags |= sharedNetworkFlagUDP
	}
	if v.HostIPv4 {
		flags |= sharedNetworkFlagHostIPv4
	}
	if v.HostIPv6 {
		flags |= sharedNetworkFlagHostIPv6
	}
	if v.BypassIPv4 {
		flags |= sharedNetworkFlagBypassIPv4
	}
	if v.BypassIPv6 {
		flags |= sharedNetworkFlagBypassIPv6
	}
	if v.IncludeSource {
		flags |= sharedNetworkFlagIncludeSource
	}
	if v.ExcludeSource {
		flags |= sharedNetworkFlagExcludeSource
	}
	if v.IncludeSourceMAC {
		flags |= sharedNetworkFlagIncludeSourceMAC
	}
	if v.ExcludeSourceMAC {
		flags |= sharedNetworkFlagExcludeSourceMAC
	}
	if v.SharedBypassPrivate {
		flags |= sharedNetworkFlagBypassPrivateAddress
	}
	if v.BypassFlowCache {
		flags |= sharedNetworkFlagBypassFlowCache
	}
	if v.FakeIPIPv4 {
		flags |= sharedNetworkFlagFakeIPIPv4
	}
	if v.FakeIPIPv6 {
		flags |= sharedNetworkFlagFakeIPIPv6
	}
	return flags
}
