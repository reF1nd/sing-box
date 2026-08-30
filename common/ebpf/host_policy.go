package ebpf

import (
	"bytes"
	"net/netip"
	"slices"
)

func compileHostAddresses(addresses []netip.Addr) ([][4]byte, [][16]byte) { //nolint:unused // Used by eBPF-tagged policy runtimes.
	ipv4Set := make(map[[4]byte]struct{})
	ipv6Set := make(map[[16]byte]struct{})
	for _, address := range addresses {
		address = address.Unmap()
		switch {
		case address.Is4():
			ipv4Set[address.As4()] = struct{}{}
		case address.Is6():
			ipv6Set[address.As16()] = struct{}{}
		}
	}
	ipv4 := make([][4]byte, 0, len(ipv4Set))
	for address := range ipv4Set {
		ipv4 = append(ipv4, address)
	}
	ipv6 := make([][16]byte, 0, len(ipv6Set))
	for address := range ipv6Set {
		ipv6 = append(ipv6, address)
	}
	slices.SortFunc(ipv4, func(left, right [4]byte) int {
		return bytes.Compare(left[:], right[:])
	})
	slices.SortFunc(ipv6, func(left, right [16]byte) int {
		return bytes.Compare(left[:], right[:])
	})
	return ipv4, ipv6
}
