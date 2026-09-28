//go:build with_ebpf && (linux || android)

package fakeip

import "net/netip"

// FakeIPRanges is intentionally available only to the eBPF inbound. Other
// builds keep the FakeIP store API unchanged.
func (s *Store) FakeIPRanges() (netip.Prefix, netip.Prefix) {
	return s.inet4Range, s.inet6Range
}
