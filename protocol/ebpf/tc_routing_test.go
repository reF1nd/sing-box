//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net/netip"
	"testing"

	"github.com/sagernet/netlink"
	commonEBPF "github.com/sagernet/sing-box/common/ebpf"

	"golang.org/x/sys/unix"
)

func TestTCPolicyRoutes(t *testing.T) {
	for _, testCase := range []struct {
		name     string
		family   int
		prefixes []netip.Prefix
	}{
		{
			"IPv4",
			unix.AF_INET,
			[]netip.Prefix{
				netip.MustParsePrefix("0.0.0.0/1"),
				netip.MustParsePrefix("128.0.0.0/1"),
			},
		},
		{
			"IPv6",
			unix.AF_INET6,
			[]netip.Prefix{
				netip.MustParsePrefix("::/1"),
				netip.MustParsePrefix("8000::/1"),
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			routes := tcPolicyRoutes(7, testCase.family)
			if len(routes) != len(testCase.prefixes) {
				t.Fatalf("unexpected route count: %d", len(routes))
			}
			wantScope := uint8(unix.RT_SCOPE_HOST)
			if testCase.family == unix.AF_INET6 {
				wantScope = unix.RT_SCOPE_UNIVERSE
			}
			for index, route := range routes {
				if route.LinkIndex != 7 || route.Family != testCase.family ||
					route.Table != tcPolicyRoutingTable || route.Type != unix.RTN_LOCAL ||
					uint8(route.Scope) != wantScope || route.Protocol != unix.RTPROT_STATIC {
					t.Fatalf("unexpected route: %+v", route)
				}
				if destination := routeDestination(route.Dst); destination != testCase.prefixes[index] {
					t.Fatalf("unexpected destination: %s", destination)
				}
			}
		})
	}
}

func TestTCPolicyRule(t *testing.T) {
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		rule := tcPolicyRule(family)
		if rule.Family != family || rule.Priority != tcPolicyRoutingPriority ||
			rule.Table != tcPolicyRoutingTable || rule.Mark != commonEBPF.DefaultTCRoutingMark ||
			!rule.MarkSet || rule.Mask != int(commonEBPF.DefaultTCRoutingMark) {
			t.Fatalf("unexpected policy rule: %+v", rule)
		}
		listed := *rule
		listed.MarkSet = false
		if !matchesTCPolicyRule(listed, *rule) {
			t.Fatal("listed policy rule did not match its expected rule")
		}
		listed.Table++
		if matchesTCPolicyRule(listed, *rule) {
			t.Fatal("conflicting policy rule matched")
		}
	}
}

func TestTCPolicyRuleMarkBits(t *testing.T) {
	unmarked := netlink.NewRule()
	if bits := tcPolicyRuleMarkBits(*unmarked); bits != 0 {
		t.Fatalf("unmarked policy rule reserved mark bits: %#x", bits)
	}

	masked := netlink.NewRule()
	masked.Mark = 0x10000
	masked.Mask = 0x1FFFF
	if bits := tcPolicyRuleMarkBits(*masked); bits != 0x1FFFF {
		t.Fatalf("unexpected masked policy rule bits: %#x", bits)
	}

	fullMask := netlink.NewRule()
	fullMask.Mark = 1
	if bits := tcPolicyRuleMarkBits(*fullMask); bits != ^uint32(0) {
		t.Fatalf("mark without an explicit mask did not reserve the full value: %#x", bits)
	}

	zeroMark := netlink.NewRule()
	zeroMark.Mask = 0xFFFF
	if bits := tcPolicyRuleMarkBits(*zeroMark); bits != 0xFFFF {
		t.Fatalf("zero-mark policy rule mask was ignored: %#x", bits)
	}
}

func TestMatchesTCPolicyRoute(t *testing.T) {
	routes := tcPolicyRoutes(7, unix.AF_INET)
	if !matchesTCPolicyRoute(routes[0], routes) {
		t.Fatal("expected route did not match")
	}
	conflict := routes[0]
	conflict.LinkIndex++
	if matchesTCPolicyRoute(conflict, routes) {
		t.Fatal("route on another interface matched")
	}
	conflict = routes[0]
	conflict.Dst = tcPolicyRoutes(7, unix.AF_INET6)[0].Dst
	if matchesTCPolicyRoute(conflict, routes) {
		t.Fatal("route with another destination matched")
	}
}
