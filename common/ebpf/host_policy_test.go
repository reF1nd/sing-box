package ebpf

import (
	"net/netip"
	"slices"
	"testing"
)

func TestCompileHostAddresses(t *testing.T) {
	ipv4, ipv6 := compileHostAddresses([]netip.Addr{
		netip.MustParseAddr("2001:db8::2"),
		netip.MustParseAddr("192.0.2.2"),
		netip.MustParseAddr("::ffff:192.0.2.1"),
		netip.MustParseAddr("2001:db8::1"),
		netip.MustParseAddr("192.0.2.2"),
		{},
	})
	if expected := [][4]byte{{192, 0, 2, 1}, {192, 0, 2, 2}}; !slices.Equal(ipv4, expected) {
		t.Fatalf("unexpected IPv4 addresses: %v", ipv4)
	}
	if expected := [][16]byte{
		netip.MustParseAddr("2001:db8::1").As16(),
		netip.MustParseAddr("2001:db8::2").As16(),
	}; !slices.Equal(ipv6, expected) {
		t.Fatalf("unexpected IPv6 addresses: %v", ipv6)
	}
}
