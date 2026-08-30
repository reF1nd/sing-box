//go:build with_ebpf && linux && ebpf_integration

package ebpf

import (
	"os"
	"testing"

	"github.com/sagernet/netlink"

	"golang.org/x/sys/unix"
)

func TestTCPolicyRoutingIntegration(t *testing.T) {
	if os.Getenv("SING_BOX_EBPF_INTEGRATION") != "1" {
		t.Skip("set SING_BOX_EBPF_INTEGRATION=1 to run eBPF integration tests")
	}
	if os.Geteuid() != 0 {
		t.Fatal("eBPF integration test requires root")
	}
	routing, err := startTCPolicyRouting(true)
	if err != nil {
		t.Fatal(err)
	}
	closed := false
	t.Cleanup(func() {
		if !closed {
			_ = routing.Close()
		}
	})
	loopback, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		expectedRoutes := tcPolicyRoutes(loopback.Attrs().Index, family)
		routes, listErr := netlink.RouteListFiltered(
			family,
			&netlink.Route{Table: tcPolicyRoutingTable},
			netlink.RT_FILTER_TABLE,
		)
		if listErr != nil {
			t.Fatal(listErr)
		}
		if len(routes) != len(expectedRoutes) {
			t.Fatalf("unexpected route count for family %d: %d", family, len(routes))
		}
		for _, route := range routes {
			if !matchesTCPolicyRoute(route, expectedRoutes) {
				t.Fatalf("unexpected route for family %d: %+v", family, route)
			}
		}
		rules, listErr := netlink.RuleList(family)
		if listErr != nil {
			t.Fatal(listErr)
		}
		matched := false
		for _, rule := range rules {
			if matchesTCPolicyRule(rule, *tcPolicyRule(family)) {
				matched = true
				break
			}
		}
		if !matched {
			t.Fatalf("missing policy rule for family %d", family)
		}
	}
	if err = netlink.RouteDel(&routing.routes[0]); err != nil {
		t.Fatal(err)
	}
	if err = netlink.RuleDel(routing.rules[0]); err != nil {
		t.Fatal(err)
	}
	changed, err := routing.ensure()
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("missing policy routing state was not restored")
	}
	changed, err = routing.ensure()
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Fatal("complete policy routing state was changed")
	}
	if err = routing.Close(); err != nil {
		t.Fatal(err)
	}
	closed = true
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		routes, listErr := netlink.RouteListFiltered(
			family,
			&netlink.Route{Table: tcPolicyRoutingTable},
			netlink.RT_FILTER_TABLE,
		)
		if listErr != nil {
			t.Fatal(listErr)
		}
		if len(routes) != 0 {
			t.Fatalf("policy routes remain for family %d", family)
		}
	}
}
