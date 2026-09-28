//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net"
	"net/netip"
	"testing"

	"github.com/sagernet/netlink"
)

// TestInterfaceRoutesIPv6Prefix exercises exact kernel route selection rather
// than inferring FakeIP reachability from unrelated addresses on an interface.
func TestInterfaceRoutesIPv6Prefix(t *testing.T) {
	enterTestNetworkNamespace(t)
	fakeIPPrefix := netip.MustParsePrefix("fc00::/18")

	attributes := netlink.NewLinkAttrs()
	attributes.Name = "sbicmprt0"
	veth := &netlink.Veth{LinkAttrs: attributes, PeerName: "sbicmprt1"}
	if err := netlink.LinkAdd(veth); err != nil {
		t.Fatalf("create veth pair: %v", err)
	}
	self, err := netlink.LinkByName("sbicmprt0")
	if err != nil {
		t.Fatalf("find veth: %v", err)
	}
	if err = netlink.LinkSetUp(self); err != nil {
		t.Fatalf("bring up veth: %v", err)
	}
	peer, err := netlink.LinkByName("sbicmprt1")
	if err != nil {
		t.Fatalf("find veth peer: %v", err)
	}
	if err = netlink.LinkSetUp(peer); err != nil {
		t.Fatalf("bring up veth peer: %v", err)
	}

	// A fresh veth carries only its auto-assigned link-local address and no
	// routes beyond the link-local /64 the kernel installs automatically;
	// that link-local-only route must not count as "routable".
	routable, err := interfaceRoutesIPv6Prefix(self, fakeIPPrefix)
	if err != nil {
		t.Fatalf("inspect routes before any global route exists: %v", err)
	}
	if routable {
		t.Fatal("interfaceRoutesIPv6Prefix = true with only a link-local route present")
	}

	globalAddress := &netlink.Addr{IPNet: &net.IPNet{IP: net.ParseIP("2001:db8::1"), Mask: net.CIDRMask(64, 128)}}
	if err = netlink.AddrAdd(self, globalAddress); err != nil {
		t.Fatalf("assign a global address: %v", err)
	}
	// An unrelated global connected route must not imply that the FakeIP
	// prefix can reach this interface.
	routable, err = interfaceRoutesIPv6Prefix(self, fakeIPPrefix)
	if err != nil {
		t.Fatalf("inspect routes after a global address exists: %v", err)
	}
	if routable {
		t.Fatal("interfaceRoutesIPv6Prefix = true with only an unrelated global route present")
	}

	fakeIPRoute := &netlink.Route{
		LinkIndex: peer.Attrs().Index,
		Dst: &net.IPNet{
			IP:   net.ParseIP("fc00::"),
			Mask: net.CIDRMask(18, 128),
		},
	}
	if err = netlink.RouteAdd(fakeIPRoute); err != nil {
		t.Fatalf("add FakeIP route through wrong interface: %v", err)
	}
	routable, err = interfaceRoutesIPv6Prefix(self, fakeIPPrefix)
	if err != nil {
		t.Fatalf("inspect route through wrong interface: %v", err)
	}
	if routable {
		t.Fatal("interfaceRoutesIPv6Prefix = true when the selected route uses another interface")
	}
	if err = netlink.RouteDel(fakeIPRoute); err != nil {
		t.Fatalf("remove FakeIP route through wrong interface: %v", err)
	}

	fakeIPRoute.LinkIndex = self.Attrs().Index
	if err = netlink.RouteAdd(fakeIPRoute); err != nil {
		t.Fatalf("add matching FakeIP route: %v", err)
	}
	routable, err = interfaceRoutesIPv6Prefix(self, fakeIPPrefix)
	if err != nil {
		t.Fatalf("inspect matching FakeIP route: %v", err)
	}
	if !routable {
		t.Fatal("interfaceRoutesIPv6Prefix = false with a matching route present")
	}
	if err = netlink.RouteDel(fakeIPRoute); err != nil {
		t.Fatalf("remove matching FakeIP route: %v", err)
	}

	defaultRoute := &netlink.Route{
		LinkIndex: self.Attrs().Index,
		Gw:        net.ParseIP("fe80::1"),
	}
	if err = netlink.RouteAdd(defaultRoute); err != nil {
		t.Fatalf("add a default route: %v", err)
	}
	// A plain default route (Dst == nil) is exactly what ordinary IPv4 FakeIP
	// interception already relies on; IPv6 must accept the same shape.
	routable, err = interfaceRoutesIPv6Prefix(self, fakeIPPrefix)
	if err != nil {
		t.Fatalf("inspect routes after a default route exists: %v", err)
	}
	if !routable {
		t.Fatal("interfaceRoutesIPv6Prefix = false with a default route present")
	}
}
