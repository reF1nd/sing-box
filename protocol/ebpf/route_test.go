//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net"
	"net/netip"
	"testing"
)

func TestRoutePrefixContains(t *testing.T) {
	tests := []struct {
		destination *net.IPNet
		prefix      netip.Prefix
		contains    bool
	}{
		{
			destination: prefixIPNet(netip.MustParsePrefix("127.0.0.0/8")),
			prefix:      netip.MustParsePrefix("127.0.0.0/8"),
			contains:    true,
		},
		{
			destination: prefixIPNet(netip.MustParsePrefix("127.0.0.0/8")),
			prefix:      netip.MustParsePrefix("127.128.0.0/9"),
			contains:    true,
		},
		{
			destination: prefixIPNet(netip.MustParsePrefix("fd53:696e:672d:626f::/48")),
			prefix:      netip.MustParsePrefix("fd53:696e:672d:626f::1/64"),
			contains:    true,
		},
		{
			destination: prefixIPNet(netip.MustParsePrefix("10.0.0.0/8")),
			prefix:      netip.MustParsePrefix("127.0.0.0/8"),
		},
		{
			destination: prefixIPNet(netip.MustParsePrefix("127.128.0.0/10")),
			prefix:      netip.MustParsePrefix("127.128.0.0/9"),
		},
		{
			destination: nil,
			prefix:      netip.MustParsePrefix("127.128.0.0/9"),
		},
	}
	for _, test := range tests {
		if routePrefixContains(test.destination, test.prefix) != test.contains {
			t.Fatalf("unexpected comparison for %v and %v", test.destination, test.prefix)
		}
	}
}

func TestPrefixesOverlap(t *testing.T) {
	tests := []struct {
		left    string
		right   string
		overlap bool
	}{
		{"127.128.0.0/9", "127.128.0.0/10", true},
		{"127.128.0.0/9", "127.0.0.0/8", true},
		{"127.128.0.0/9", "127.0.0.0/9", false},
		{"fd53:696e:672d:626f::/64", "fd53:696e:672d:626f::1/128", true},
		{"fd53:696e:672d:626f::/64", "fd00::/64", false},
		{"127.128.0.0/9", "fd53:696e:672d:626f::/64", false},
	}
	for _, test := range tests {
		left := netip.MustParsePrefix(test.left)
		right := netip.MustParsePrefix(test.right)
		if overlap := prefixesOverlap(left, right); overlap != test.overlap {
			t.Errorf("unexpected overlap for %s and %s: got %v, want %v",
				test.left, test.right, overlap, test.overlap)
		}
	}
}
