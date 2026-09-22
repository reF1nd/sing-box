//go:build with_ebpf && (linux || android)

package ebpf

import "net/netip"

func prefixesOverlap(left netip.Prefix, right netip.Prefix) bool {
	if !left.IsValid() || !right.IsValid() || left.Addr().Is4() != right.Addr().Is4() {
		return false
	}
	left = left.Masked()
	right = right.Masked()
	return left.Contains(right.Addr()) || right.Contains(left.Addr())
}
