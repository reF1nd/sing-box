//go:build with_ebpf && (linux || android)

package ebpf

const (
	ProtocolTCP = 6
	ProtocolUDP = 17

	SocketMetadataSelfBypass      = 1 << 0
	SocketMetadataPolicyBypass    = 1 << 1
	SocketMetadataPolicyIntercept = 1 << 2

	addressFamilyIPv4 = 2
	addressFamilyIPv6 = 10
)

type DNSMode uint16

const (
	DNSModeHijack DNSMode = iota
	DNSModeRespectPolicy
	DNSModeOff
)

type UIDRange struct {
	Start uint32
	End   uint32
}

type LocalPolicy struct {
	EnableBypassCIDR     bool
	DNSMode              DNSMode
	BypassPrivateAddress bool
	IncludeUIDConfigured bool
	IncludeUID           []UIDRange
	ExcludeUID           []UIDRange
}

type MACAddress [6]byte

type tcMACKey struct {
	Address  MACAddress
	Reserved [2]byte
}
