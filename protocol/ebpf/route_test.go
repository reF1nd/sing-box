//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/sagernet/netlink"
	M "github.com/sagernet/sing/common/metadata"
)

func TestRestoreOriginalSource(t *testing.T) {
	source := M.SocksaddrFrom(netip.MustParseAddr("127.0.0.1"), 23456)
	destination := netip.MustParseAddr("1.1.1.1")
	result, err := restoreOriginalSourceWithRouteGet(source, destination, 10001, func(
		lookupDestination net.IP,
		options *netlink.RouteGetOptions,
	) ([]netlink.Route, error) {
		if !lookupDestination.Equal(net.ParseIP("1.1.1.1")) {
			t.Fatalf("unexpected route destination: %s", lookupDestination)
		}
		if options == nil || options.UID == nil || *options.UID != 10001 {
			t.Fatalf("unexpected route UID options: %+v", options)
		}
		return []netlink.Route{{Src: net.ParseIP("192.0.2.10")}}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if result != M.SocksaddrFrom(netip.MustParseAddr("192.0.2.10"), 23456) {
		t.Fatalf("unexpected restored source: %s", result)
	}
}

func TestRestoreOriginalSourceIPv6(t *testing.T) {
	source := M.SocksaddrFrom(netip.IPv6Loopback(), 34567)
	result, err := restoreOriginalSourceWithRouteGet(
		source,
		netip.MustParseAddr("2001:db8::1"),
		0,
		func(net.IP, *netlink.RouteGetOptions) ([]netlink.Route, error) {
			return []netlink.Route{{Src: net.ParseIP("2001:db8::10")}}, nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if result != M.SocksaddrFrom(netip.MustParseAddr("2001:db8::10"), 34567) {
		t.Fatalf("unexpected restored source: %s", result)
	}
}

func TestRestoreOriginalSourcePreservesBoundAddress(t *testing.T) {
	source := M.SocksaddrFrom(netip.MustParseAddr("192.0.2.20"), 45678)
	called := false
	result, err := restoreOriginalSourceWithRouteGet(
		source,
		netip.MustParseAddr("1.1.1.1"),
		10001,
		func(net.IP, *netlink.RouteGetOptions) ([]netlink.Route, error) {
			called = true
			return nil, nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if called || result != source {
		t.Fatalf("explicit source was not preserved: %s", result)
	}
}

func TestRestoreOriginalSourceFallback(t *testing.T) {
	source := M.SocksaddrFrom(netip.MustParseAddr("127.0.0.1"), 56789)
	result, err := restoreOriginalSourceWithRouteGet(
		source,
		netip.MustParseAddr("1.1.1.1"),
		10001,
		func(net.IP, *netlink.RouteGetOptions) ([]netlink.Route, error) {
			return nil, errors.New("route lookup failed")
		},
	)
	if err == nil {
		t.Fatal("expected route lookup failure")
	}
	if result != source {
		t.Fatalf("source changed after lookup failure: %s", result)
	}
}

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
