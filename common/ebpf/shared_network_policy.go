package ebpf

import (
	"net/netip"
	"slices"
)

func compileHostPrefixes(addresses []netip.Addr) ([]netip.Prefix, []netip.Prefix) { //nolint:unused // Used by eBPF-tagged policy runtimes.
	ipv4Set := make(map[netip.Prefix]struct{})
	ipv6Set := make(map[netip.Prefix]struct{})
	for _, address := range addresses {
		address = address.Unmap()
		switch {
		case address.Is4():
			ipv4Set[netip.PrefixFrom(address, 32)] = struct{}{}
		case address.Is6():
			ipv6Set[netip.PrefixFrom(address, 128)] = struct{}{}
		}
	}
	ipv4 := make([]netip.Prefix, 0, len(ipv4Set))
	for prefix := range ipv4Set {
		ipv4 = append(ipv4, prefix)
	}
	ipv6 := make([]netip.Prefix, 0, len(ipv6Set))
	for prefix := range ipv6Set {
		ipv6 = append(ipv6, prefix)
	}
	slices.SortFunc(ipv4, func(left, right netip.Prefix) int {
		return left.Addr().Compare(right.Addr())
	})
	slices.SortFunc(ipv6, func(left, right netip.Prefix) int {
		return left.Addr().Compare(right.Addr())
	})
	return ipv4, ipv6
}
