package ebpf

import (
	"net/netip"

	E "github.com/sagernet/sing/common/exceptions"
)

const (
	ProtocolTCP            = 6
	ProtocolUDP            = 17
	TCPRedirectMapCapacity = 65536
	UDPRedirectMapCapacity = 65536

	addressFamilyIPv4 = 2
	addressFamilyIPv6 = 10
)

type RuntimeStats struct {
	TCPRedirectEntries uint64
	UDPRedirectEntries uint64
	TokenCollisions    uint64
	MapUpdateFailures  uint64
	RedirectDrops      uint64
	LookupMisses       uint64
}

type OriginalDestination struct {
	Destination  netip.AddrPort
	ConnectedUDP bool
	UID          uint32
}

type redirectKey struct {
	Family       uint8
	Protocol     uint8
	RedirectPort uint16
	RedirectAddr [16]byte
}

type originalDestination struct {
	Family       uint8
	Protocol     uint8
	Port         uint16
	Addr         [16]byte
	Flags        uint8
	Reserved     [3]byte
	SocketCookie uint64
	UID          uint32
	ReservedTail uint32
}

func makeRedirectKey(protocol uint8, redirect netip.AddrPort) (redirectKey, error) {
	var key redirectKey
	key.Protocol = protocol
	key.RedirectPort = redirect.Port()
	if err := putAddress(&key.Family, &key.RedirectAddr, redirect.Addr()); err != nil {
		return redirectKey{}, E.Cause(err, "invalid redirect address")
	}
	return key, nil
}

func putAddress(family *uint8, destination *[16]byte, source netip.Addr) error {
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
