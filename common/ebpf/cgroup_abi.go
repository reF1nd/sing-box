package ebpf

import (
	"net/netip"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
)

const (
	ProtocolTCP                = 6
	ProtocolUDP                = 17
	TCPRedirectMapCapacity     = 65536
	UDPRedirectMapCapacity     = 65536
	SocketBypassMapCapacity    = 65536
	SharedNetworkMapCapacity   = 65536
	MaxConfigurableMapCapacity = 1 << 20
	udpFlowActionProxy         = 1
	udpFlowActionBypass        = 2

	addressFamilyIPv4 = 2
	addressFamilyIPv6 = 10
)

type CgroupMapCapacity struct {
	TCPRedirect  uint32
	UDPRedirect  uint32
	SocketBypass uint32
}

type CgroupConfig struct {
	Path          string
	EnableTCP     bool
	EnableUDP     bool
	EnableIPv6    bool
	AutoIPv6      bool
	IPv6Available bool
	RedirectIPv4  netip.Prefix
	RedirectIPv6  netip.Prefix
	MapCapacity   CgroupMapCapacity
	UDPTimeout    time.Duration
	Policy        CgroupPolicy
}

func DefaultCgroupMapCapacity() CgroupMapCapacity {
	return CgroupMapCapacity{
		TCPRedirect:  TCPRedirectMapCapacity,
		UDPRedirect:  UDPRedirectMapCapacity,
		SocketBypass: SocketBypassMapCapacity,
	}
}

type OriginalDestination struct {
	Destination  netip.AddrPort
	ConnectedUDP bool
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
