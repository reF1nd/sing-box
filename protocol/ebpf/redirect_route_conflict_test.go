//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net"
	"net/netip"
	"testing"

	"github.com/sagernet/netlink"

	commonEBPF "github.com/CHIZI-0618/sing-ebpf"
)

// TestCheckRedirectRouteConflictSeesARouteOnAnotherInterface proves the
// conflict check actually inspects routes system-wide, not just on the
// loopback interface it also inspects addresses on — the case
// netlink.RouteList(nil, family)'s interface-index-zero filtering silently
// hid (see redirect_route.go's own comment on the fix).
func TestCheckRedirectRouteConflictSeesARouteOnAnotherInterface(t *testing.T) {
	enterTestNetworkNamespace(t)

	loopback, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatalf("find loopback: %v", err)
	}
	if err = netlink.LinkSetUp(loopback); err != nil {
		t.Fatalf("bring up loopback: %v", err)
	}

	attributes := netlink.NewLinkAttrs()
	attributes.Name = "sbredirect0"
	veth := &netlink.Veth{LinkAttrs: attributes, PeerName: "sbredirect1"}
	if err = netlink.LinkAdd(veth); err != nil {
		t.Fatalf("create veth pair: %v", err)
	}
	self, err := netlink.LinkByName("sbredirect0")
	if err != nil {
		t.Fatalf("find veth: %v", err)
	}
	if err = netlink.LinkSetUp(self); err != nil {
		t.Fatalf("bring up veth: %v", err)
	}

	candidate := redirectIPv6Candidates[0]
	conflicting := &netlink.Route{
		LinkIndex: self.Attrs().Index,
		Dst: &net.IPNet{
			IP:   net.IP(candidate.Addr().AsSlice()),
			Mask: net.CIDRMask(candidate.Bits(), candidate.Addr().BitLen()),
		},
	}
	if err = netlink.RouteAdd(conflicting); err != nil {
		t.Fatalf("add a conflicting route on a non-loopback interface: %v", err)
	}

	if _, err = commonEBPF.SelectRedirectPrefix(netlink.FAMILY_V6, []netip.Prefix{candidate}, nil); err == nil {
		t.Fatalf("checkRedirectRouteConflict missed a route on interface %s conflicting with %s", self.Attrs().Name, candidate)
	}
}

// TestCheckRedirectRouteConflictSeesANonMainTableRoute proves the conflict
// check also inspects routes outside the main table — a route reachable
// only through an ip rule this process never installed is exactly as real a
// conflict for the internal redirect address as one in the main table.
//
// The conflicting route goes on a veth, not loopback: checkRedirectRouteConflict
// deliberately ignores IPv4 routes on the loopback interface specifically
// (that is where addLocalRoute installs the redirect prefix's own route, so
// treating it as a conflict with itself would make every second reconcile
// pass fail), which would otherwise mask what this test means to check —
// the table dimension — behind that unrelated, correct exclusion.
func TestCheckRedirectRouteConflictSeesANonMainTableRoute(t *testing.T) {
	enterTestNetworkNamespace(t)

	loopback, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatalf("find loopback: %v", err)
	}
	if err = netlink.LinkSetUp(loopback); err != nil {
		t.Fatalf("bring up loopback: %v", err)
	}
	attributes := netlink.NewLinkAttrs()
	attributes.Name = "sbredirect2"
	veth := &netlink.Veth{LinkAttrs: attributes, PeerName: "sbredirect3"}
	if err = netlink.LinkAdd(veth); err != nil {
		t.Fatalf("create veth pair: %v", err)
	}
	self, err := netlink.LinkByName("sbredirect2")
	if err != nil {
		t.Fatalf("find veth: %v", err)
	}
	if err = netlink.LinkSetUp(self); err != nil {
		t.Fatalf("bring up veth: %v", err)
	}

	candidate := redirectIPv4Candidates[0]
	const customTable = 2100
	conflicting := &netlink.Route{
		LinkIndex: self.Attrs().Index,
		Dst: &net.IPNet{
			IP:   net.IP(candidate.Addr().AsSlice()),
			Mask: net.CIDRMask(candidate.Bits(), candidate.Addr().BitLen()),
		},
		Table: customTable,
	}
	if err = netlink.RouteAdd(conflicting); err != nil {
		t.Fatalf("add a conflicting route in table %d: %v", customTable, err)
	}

	if _, err = commonEBPF.SelectRedirectPrefix(netlink.FAMILY_V4, []netip.Prefix{candidate}, nil); err == nil {
		t.Fatalf("checkRedirectRouteConflict missed a route in non-main table %d conflicting with %s", customTable, candidate)
	}
}
