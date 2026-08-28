//go:build with_ebpf && (linux || android)

package ebpf

import (
	"math"
	"net"
	"net/netip"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
)

const sharedNetworkTCPReleaseGrace = time.Second

type SharedNetworkConfig struct {
	ListenerPort         uint16
	EnableTCP            bool
	EnableUDP            bool
	DNSMode              DNSMode
	BypassPrivateAddress bool
	RedirectIPv4         netip.Prefix
	RedirectIPv6         netip.Prefix
	FakeIPIPv4           netip.Prefix
	FakeIPIPv6           netip.Prefix
	IncludeSourceCIDR    []netip.Prefix
	ExcludeSourceCIDR    []netip.Prefix
	IncludeSourceMAC     []MACAddress
	ExcludeSourceMAC     []MACAddress
	MapCapacity          SharedNetworkMapCapacities
	UDPTimeout           time.Duration
}

type MACAddress [6]byte

type sharedNetworkMACKey struct {
	Address  MACAddress
	Reserved [2]byte
}

type sharedNetworkControl struct {
	Enabled             uint32
	Flags               uint32
	ListenerPort        uint16
	DNSMode             DNSMode
	TokenIPv4Prefix     [4]byte
	TokenIPv4PrefixBits uint8
	TokenIPv6PrefixBits uint8
	Reserved2           [2]byte
	TokenIPv6Prefix     [16]byte
	UDPTimeoutSeconds   uint32
	FakeIPIPv4Prefix    [4]byte
	FakeIPIPv4Mask      [4]byte
	FakeIPIPv6Prefix    [16]byte
	FakeIPIPv6Mask      [16]byte
}

func sharedNetworkUDPTimeoutSeconds(timeout time.Duration) (uint32, error) {
	return normalizedUDPTimeoutSeconds("shared-network", timeout)
}

func cgroupUDPTimeoutSeconds(timeout time.Duration) (uint32, error) {
	return normalizedUDPTimeoutSeconds("local cgroup", timeout)
}

func normalizedUDPTimeoutSeconds(scope string, timeout time.Duration) (uint32, error) {
	if timeout <= 0 {
		return 0, E.New("invalid ", scope, " UDP timeout: ", timeout)
	}
	seconds := uint64(timeout / time.Second)
	if timeout%time.Second != 0 {
		seconds++
	}
	if seconds > math.MaxUint32 {
		return 0, E.New(scope, " UDP timeout is too large: ", timeout)
	}
	return uint32(seconds), nil
}

type sharedNetworkListenerKey struct {
	Family       uint8
	Protocol     uint8
	ListenerPort uint16
	TokenAddr    [16]byte
	ClientPort   uint16
	Reserved     uint16
	ClientAddr   [16]byte
}

type sharedNetworkOriginalKey struct {
	InterfaceIndex uint32
	Family         uint8
	Protocol       uint8
	ClientPort     uint16
	OriginalPort   uint16
	Reserved       uint16
	ClientAddr     [16]byte
	OriginalAddr   [16]byte
}

type sharedNetworkTokenValue struct {
	TokenAddr  [16]byte
	Generation uint64
	LastSeenNS uint64
	Reserved   uint64
}

type sharedNetworkOriginalValue struct {
	Family         uint8
	Protocol       uint8
	Port           uint16
	Addr           [16]byte
	InterfaceIndex uint32
	Generation     uint64
	SourceMAC      [6]byte
	Reserved2      [2]byte
}

type SharedNetworkFlowHandle struct {
	originalKey sharedNetworkOriginalKey
	listenerKey sharedNetworkListenerKey
	generation  uint64
}

type SharedNetworkFlowSweepResult struct {
	Scanned  uint32
	Removed  uint32
	Retained uint32
	Usage    MapUsage
	Complete bool
}

const (
	sharedNetworkFlagIPv4 = 1 << iota
	sharedNetworkFlagIPv6
	sharedNetworkFlagTCP
	sharedNetworkFlagUDP
	_
	sharedNetworkFlagHostIPv4
	sharedNetworkFlagHostIPv6
	sharedNetworkFlagBypassIPv4
	sharedNetworkFlagBypassIPv6
	sharedNetworkFlagIncludeSource
	sharedNetworkFlagExcludeSource
	sharedNetworkFlagIncludeSourceMAC
	sharedNetworkFlagExcludeSourceMAC
	sharedNetworkFlagBypassPrivateAddress
	sharedNetworkFlagBypassFlowCache
	_
	sharedNetworkFlagFakeIPIPv4
	sharedNetworkFlagFakeIPIPv6
)

const sharedNetworkPolicyFlags = sharedNetworkFlagHostIPv4 |
	sharedNetworkFlagHostIPv6 |
	sharedNetworkFlagBypassIPv4 |
	sharedNetworkFlagBypassIPv6 |
	sharedNetworkFlagIncludeSource |
	sharedNetworkFlagExcludeSource |
	sharedNetworkFlagIncludeSourceMAC |
	sharedNetworkFlagExcludeSourceMAC |
	sharedNetworkFlagBypassFlowCache

const sharedNetworkBypassFlowPolicyFlags = sharedNetworkFlagBypassIPv4 |
	sharedNetworkFlagBypassIPv6 |
	sharedNetworkFlagIncludeSource |
	sharedNetworkFlagExcludeSource |
	sharedNetworkFlagIncludeSourceMAC |
	sharedNetworkFlagExcludeSourceMAC

func sharedNetworkBypassFlowCacheRequired(flags uint32) bool {
	return flags&sharedNetworkBypassFlowPolicyFlags != 0
}

func makeSharedNetworkListenerKey(
	protocol uint8,
	client netip.AddrPort,
	tokenDestination netip.AddrPort,
) (sharedNetworkListenerKey, error) {
	var key sharedNetworkListenerKey
	key.Protocol = protocol
	key.ListenerPort = tokenDestination.Port()
	key.ClientPort = client.Port()
	if err := encodeAddress(&key.Family, &key.TokenAddr, tokenDestination.Addr()); err != nil {
		return sharedNetworkListenerKey{}, E.Cause(err, "invalid shared-network redirect address")
	}
	var clientFamily uint8
	if err := encodeAddress(&clientFamily, &key.ClientAddr, client.Addr()); err != nil {
		return sharedNetworkListenerKey{}, E.Cause(err, "invalid shared-network client address")
	}
	if clientFamily != key.Family {
		return sharedNetworkListenerKey{}, E.New("shared-network client and redirect address families do not match")
	}
	return key, nil
}

func sharedNetworkOriginalAddress(value sharedNetworkOriginalValue) (netip.Addr, error) {
	return sharedNetworkAddress(value.Family, value.Addr)
}

func sharedNetworkAddress(family uint8, address [16]byte) (netip.Addr, error) {
	switch family {
	case addressFamilyIPv4:
		return netip.AddrFrom4([4]byte(address[:4])), nil
	case addressFamilyIPv6:
		return netip.AddrFrom16(address), nil
	default:
		return netip.Addr{}, E.New("invalid shared-network address family: ", family)
	}
}

func sharedNetworkOriginalMAC(value sharedNetworkOriginalValue) net.HardwareAddr {
	return append(net.HardwareAddr(nil), value.SourceMAC[:]...)
}

func makeSharedNetworkFlowHandle(key sharedNetworkListenerKey, value sharedNetworkOriginalValue) SharedNetworkFlowHandle {
	return SharedNetworkFlowHandle{
		originalKey: sharedNetworkOriginalKey{
			InterfaceIndex: value.InterfaceIndex,
			Family:         key.Family,
			Protocol:       key.Protocol,
			ClientPort:     key.ClientPort,
			OriginalPort:   value.Port,
			ClientAddr:     key.ClientAddr,
			OriginalAddr:   value.Addr,
		},
		listenerKey: key,
		generation:  value.Generation,
	}
}

func makeSharedNetworkFlowHandleFromOriginal(
	key sharedNetworkOriginalKey,
	token [16]byte,
	listenerPort uint16,
	generation uint64,
) SharedNetworkFlowHandle {
	return SharedNetworkFlowHandle{
		originalKey: key,
		listenerKey: sharedNetworkListenerKey{
			Family: key.Family, Protocol: key.Protocol, ListenerPort: listenerPort,
			TokenAddr: token, ClientPort: key.ClientPort, ClientAddr: key.ClientAddr,
		},
		generation: generation,
	}
}
