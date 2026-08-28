//go:build with_ebpf && (linux || android)

package ebpf

import (
	"encoding/binary"
	"net"
	"net/netip"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
)

const (
	ProtocolTCP                         = 6
	ProtocolUDP                         = 17
	TCPRedirectMapCapacity              = 32768
	UDPRedirectMapCapacity              = 32768
	UDPPeerMapCapacity                  = 16384
	UDPFlowMapCapacity                  = 16384
	SocketBypassMapCapacity             = 32768
	SharedNetworkProxyCapacity          = 32768
	SharedNetworkBypassCapacity         = 16384
	UDPRecoveryMapCapacity              = 8192
	MaxConfigurableMapCapacity          = 1 << 20
	cgroupStatTCPRedirectFailure        = 0
	originalDestinationFlagConnectedUDP = 1
	udpFlowActionProxy                  = 1
	udpFlowActionBypass                 = 2

	addressFamilyIPv4 = 2
	addressFamilyIPv6 = 10
)

const (
	cgroupFlagTCP = 1 << iota
	cgroupFlagUDP
	cgroupFlagIPv4
	cgroupFlagIPv6
	_
	cgroupFlagUIDPolicy
	cgroupFlagUIDDefaultBypass
	cgroupFlagBypassIPv4
	cgroupFlagBypassIPv6
	_
	cgroupFlagUDPFlow
	cgroupFlagBypassPrivateAddress
	_
	cgroupFlagHostIPv4
	cgroupFlagHostIPv6
	cgroupFlagFakeIPIPv4
	cgroupFlagFakeIPIPv6
)

type cgroupControl struct {
	Flags                uint32
	Reserved             uint32
	UDPTimeoutSeconds    uint32
	RedirectIPv4Prefix   uint32
	RedirectIPv4HostMask uint32
	ListenerPort         uint16
	DNSMode              DNSMode
	RedirectIPv6Prefix   [8]byte
	FakeIPIPv4Prefix     [4]byte
	FakeIPIPv4Mask       [4]byte
	FakeIPIPv6Prefix     [16]byte
	FakeIPIPv6Mask       [16]byte
}

type udpPeerKey struct {
	SocketCookie uint64
}

type udpPeerValue struct {
	Family   uint8
	Protocol uint8
	Port     uint16
	Addr     [16]byte
}

func cgroupIPv4Redirect(prefix netip.Prefix) (uint32, uint32) {
	if !prefix.IsValid() {
		return 0, 0
	}
	hostMask := uint32(1<<(32-prefix.Bits())) - 1
	return binary.BigEndian.Uint32(prefix.Addr().AsSlice()) &^ hostMask, hostMask
}

type CgroupMapCapacity struct {
	TCPRedirect  uint32
	UDPRedirect  uint32
	UDPPeer      uint32
	UDPFlow      uint32
	SocketBypass uint32
}

type MapUsage struct {
	Entries  uint32
	Capacity uint32
}

type CgroupTCPRedirectSweepResult struct {
	Scanned  uint32
	Removed  uint32
	Complete bool
}

type SharedNetworkMapCapacities struct {
	Proxy  uint32
	Bypass uint32
}

func DefaultSharedNetworkMapCapacities() SharedNetworkMapCapacities {
	return SharedNetworkMapCapacities{
		Proxy:  SharedNetworkProxyCapacity,
		Bypass: SharedNetworkBypassCapacity,
	}
}

type CgroupConfig struct {
	Path         string
	EnableTCP    bool
	EnableUDP    bool
	EnableIPv6   bool
	RedirectIPv4 netip.Prefix
	RedirectIPv6 netip.Prefix
	FakeIPIPv4   netip.Prefix
	FakeIPIPv6   netip.Prefix
	MapCapacity  CgroupMapCapacity
	UDPTimeout   time.Duration
	Policy       CgroupPolicy
}

func DefaultCgroupMapCapacity() CgroupMapCapacity {
	return CgroupMapCapacity{
		TCPRedirect:  TCPRedirectMapCapacity,
		UDPRedirect:  UDPRedirectMapCapacity,
		UDPPeer:      UDPPeerMapCapacity,
		UDPFlow:      UDPFlowMapCapacity,
		SocketBypass: SocketBypassMapCapacity,
	}
}

type OriginalDestination struct {
	Destination  netip.AddrPort
	ConnectedUDP bool
	SourceMAC    net.HardwareAddr
}

type listenerLookupKey struct {
	Family       uint8
	Protocol     uint8
	ListenerPort uint16
	TokenAddr    [16]byte
}

type originalDestinationValue struct {
	Family       uint8
	Protocol     uint8
	Port         uint16
	Addr         [16]byte
	Flags        uint8
	Reserved     [3]byte
	SocketCookie uint64
	CreatedAtNS  uint64
}

type udpFlowKey struct {
	SocketCookie uint64
	Family       uint8
	Protocol     uint8
	Port         uint16
	Addr         [16]byte
	Reserved     [4]byte
}

type udpFlowValue struct {
	Action          uint8
	Reserved        [3]byte
	LastSeenSeconds uint32
	Listener        listenerLookupKey
	Reserved2       [4]byte
}

func makeUDPFlowKey(original originalDestinationValue) udpFlowKey {
	return udpFlowKey{
		SocketCookie: original.SocketCookie,
		Family:       original.Family,
		Protocol:     ProtocolUDP,
		Port:         original.Port,
		Addr:         original.Addr,
	}
}

func originalDestinationFromValue(original originalDestinationValue) (OriginalDestination, error) {
	var address netip.Addr
	switch original.Family {
	case addressFamilyIPv4:
		address = netip.AddrFrom4([4]byte(original.Addr[:4]))
	case addressFamilyIPv6:
		address = netip.AddrFrom16(original.Addr)
	default:
		return OriginalDestination{}, E.New("invalid original destination family: ", original.Family)
	}
	return OriginalDestination{
		Destination:  netip.AddrPortFrom(address.Unmap(), original.Port),
		ConnectedUDP: original.Flags&originalDestinationFlagConnectedUDP != 0,
	}, nil
}

func originalDestinationFromUDPPeer(cookie uint64, peer udpPeerValue) (originalDestinationValue, error) {
	if cookie == 0 {
		return originalDestinationValue{}, E.New("invalid connected UDP socket cookie")
	}
	if peer.Protocol != ProtocolUDP {
		return originalDestinationValue{}, E.New("invalid connected UDP peer protocol: ", peer.Protocol)
	}
	value := originalDestinationValue{
		Family:       peer.Family,
		Protocol:     ProtocolUDP,
		Port:         peer.Port,
		Addr:         peer.Addr,
		Flags:        originalDestinationFlagConnectedUDP,
		SocketCookie: cookie,
	}
	original, err := originalDestinationFromValue(value)
	if err != nil {
		return originalDestinationValue{}, err
	}
	if !original.Destination.IsValid() || original.Destination.Port() == 0 || original.Destination.Addr().IsUnspecified() {
		return originalDestinationValue{}, E.New("invalid connected UDP peer destination: ", original.Destination)
	}
	return value, nil
}

func makeListenerLookupKey(protocol uint8, listenerDestination netip.AddrPort) (listenerLookupKey, error) {
	var key listenerLookupKey
	key.Protocol = protocol
	key.ListenerPort = listenerDestination.Port()
	if err := encodeAddress(&key.Family, &key.TokenAddr, listenerDestination.Addr()); err != nil {
		return listenerLookupKey{}, E.Cause(err, "invalid redirect address")
	}
	return key, nil
}

func encodeAddress(family *uint8, destination *[16]byte, source netip.Addr) error {
	source = source.Unmap()
	if source.Is4() {
		*family = addressFamilyIPv4
		address := source.As4()
		copy(destination[:4], address[:])
		return nil
	}
	if source.Is6() {
		*family = addressFamilyIPv6
		address := source.As16()
		copy(destination[:], address[:])
		return nil
	}
	return E.New("invalid IP address")
}
