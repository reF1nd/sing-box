//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net/netip"
	"reflect"
	"testing"

	commonEBPF "github.com/CHIZI-0618/sing-ebpf"
)

func TestCompileActionPolicyKeepsDestinationSemanticsInSync(t *testing.T) {
	var local, shared commonEBPF.ActionScope
	fakeIPv4 := netip.MustParsePrefix("198.18.0.0/15")
	fakeIPv6 := netip.MustParsePrefix("fd00:eb0f::/48")
	ports := []portRange{{Start: 443, End: 443}}
	appendDestinationPolicy(&local, true, ports, dnsModeRespectPolicy, fakeIPv4, fakeIPv6, nil, true, true)
	appendDestinationPolicy(&shared, true, ports, dnsModeRespectPolicy, fakeIPv4, fakeIPv6, nil, true, true)
	if !reflect.DeepEqual(local.DestinationCIDR, shared.DestinationCIDR) {
		t.Fatalf("local/shared destination CIDR semantics diverged:\nlocal=%+v\nshared=%+v", local.DestinationCIDR, shared.DestinationCIDR)
	}
	if !reflect.DeepEqual(local.DestinationPort, shared.DestinationPort) {
		t.Fatalf("local/shared destination port semantics diverged:\nlocal=%+v\nshared=%+v", local.DestinationPort, shared.DestinationPort)
	}
}

func TestSharedSourceDefaultPreservesIncludePolicy(t *testing.T) {
	for _, test := range []struct {
		cidrs, macs int
		want        commonEBPF.Decision
	}{
		{0, 0, commonEBPF.DecisionIntercept},
		{1, 0, commonEBPF.DecisionPass},
		{0, 1, commonEBPF.DecisionPass},
		{1, 1, commonEBPF.DecisionPass},
	} {
		if got := sharedSourceDefault(test.cidrs, test.macs); got != test.want {
			t.Fatalf("CIDRs=%d MACs=%d: default=%v, want %v", test.cidrs, test.macs, got, test.want)
		}
	}
}

func TestPrivateBypassOptionsRemainIndependent(t *testing.T) {
	for _, local := range []bool{false, true} {
		for _, shared := range []bool{false, true} {
			inbound := &Inbound{
				localPolicy:         localUIDPolicy{BypassPrivateAddress: local},
				sharedBypassPrivate: shared,
				enableTCP:           true,
				enableUDP:           true,
			}
			if _, err := inbound.compileActionPolicy(); err != nil {
				t.Fatal(err)
			}
			for _, scope := range []struct {
				enabled   bool
				decisions []commonEBPF.CIDRDecision
			}{{local, inbound.localInitialDestinations}, {shared, inbound.sharedInitialDestinations}} {
				if !scope.enabled {
					if len(scope.decisions) != 0 {
						t.Fatalf("disabled private bypass emitted rules: %+v", scope.decisions)
					}
					continue
				}
				if len(scope.decisions) != len(eBPFPrivateDestinationPrefixes) {
					t.Fatal("private bypass lost address ranges")
				}
				for index, prefix := range eBPFPrivateDestinationPrefixes {
					if scope.decisions[index] != (commonEBPF.CIDRDecision{Prefix: prefix, Action: commonEBPF.DecisionPass}) {
						t.Fatalf("private range %v lost its pass action", prefix)
					}
				}
			}
		}
	}
}

func TestCompileProcessUIDPolicySubtractsExcludedRanges(t *testing.T) {
	inbound := &Inbound{
		localPolicy: localUIDPolicy{
			IncludeUIDConfigured: true,
			IncludeUID:           []uidRange{{Start: 1000, End: 1999}},
			ExcludeUID:           []uidRange{{Start: 1400, End: 1499}},
		},
	}
	decisions, defaultAction := inbound.compileProcessUIDPolicy()
	if defaultAction != commonEBPF.DecisionPass {
		t.Fatalf("default action = %v, want pass", defaultAction)
	}
	want := []commonEBPF.UIDDecision{
		{Start: 1000, End: 1399, Action: commonEBPF.DecisionIntercept},
		{Start: 1500, End: 1999, Action: commonEBPF.DecisionIntercept},
	}
	if len(decisions) != len(want) {
		t.Fatalf("decisions = %+v, want %+v", decisions, want)
	}
	for index := range want {
		if decisions[index] != want[index] {
			t.Fatalf("decisions = %+v, want %+v", decisions, want)
		}
	}
}

func TestCompileProcessUIDPolicyUsesExcludeActionsByDefault(t *testing.T) {
	inbound := &Inbound{localPolicy: localUIDPolicy{
		ExcludeUID: []uidRange{{Start: 10000, End: 10010}},
	}}
	decisions, defaultAction := inbound.compileProcessUIDPolicy()
	if defaultAction != commonEBPF.DecisionIntercept {
		t.Fatalf("default action = %v, want intercept", defaultAction)
	}
	if len(decisions) != 1 || decisions[0].Action != commonEBPF.DecisionPass {
		t.Fatalf("decisions = %+v, want one pass decision", decisions)
	}
}

func TestCombineDestinationDecisionsRetainsStaticPasses(t *testing.T) {
	inbound := &Inbound{}
	combined, err := inbound.combineDestinationDecisions(
		[]commonEBPF.CIDRDecision{{
			Prefix: netip.MustParsePrefix("192.168.0.0/16"), Action: commonEBPF.DecisionPass,
		}},
		[]commonEBPF.CIDRDecision{{
			Prefix: netip.MustParsePrefix("203.0.113.0/24"), Action: commonEBPF.DecisionPass,
		}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(combined) != 2 {
		t.Fatalf("combined decisions = %+v, want static and dynamic pass entries", combined)
	}
}

func TestAppendDestinationPolicyForcesBypassExclude(t *testing.T) {
	var scope commonEBPF.ActionScope
	appendDestinationPolicy(&scope, true, nil, dnsModeRespectPolicy,
		netip.Prefix{}, netip.Prefix{},
		[]netip.Prefix{netip.MustParsePrefix("100.64.0.0/10")},
		true, true)
	var forced bool
	for _, decision := range scope.DestinationCIDR {
		if decision.Prefix == netip.MustParsePrefix("100.64.0.0/10") && decision.Action == commonEBPF.DecisionIntercept {
			forced = true
		}
	}
	if !forced {
		t.Fatalf("bypass_exclude prefix was not emitted as force-intercept: %+v", scope.DestinationCIDR)
	}
}

func TestNormalizeBypassExclude(t *testing.T) {
	v4 := netip.MustParsePrefix("100.64.0.0/10")
	v6 := netip.MustParsePrefix("fd7a:115c:a1e0::/48")
	if got, err := normalizeCIDRs("local.bypass_exclude", []netip.Prefix{v4, v6}); err != nil || len(got) != 2 {
		t.Fatalf("valid v4+v6 rejected: %v, %v", got, err)
	}
	if _, err := normalizeCIDRs("local.bypass_exclude", []netip.Prefix{v4, netip.MustParsePrefix("10.0.0.0/8")}); err != nil {
		t.Fatal(err)
	}
	if _, err := normalizeCIDRs("local.bypass_exclude", []netip.Prefix{v6, netip.MustParsePrefix("fd00::/8")}); err != nil {
		t.Fatal(err)
	}
	// IPv4-mapped IPv6 is converted to its IPv4 form, not rejected outright.
	mapped, err := normalizeCIDRs("local.bypass_exclude", []netip.Prefix{netip.MustParsePrefix("::ffff:100.64.0.0/104")})
	if err != nil || len(mapped) != 1 || mapped[0].String() != "100.0.0.0/8" {
		t.Fatalf("IPv4-mapped IPv6 not converted to IPv4: %v, %v", mapped, err)
	}
	if got, err := normalizeCIDRs("local.bypass_exclude", nil); err != nil || got != nil {
		t.Fatalf("empty input: got %v, %v", got, err)
	}
}

func TestIndependentForcePrefixesWithFakeIP(t *testing.T) {
	i := &Inbound{
		enableTCP: true, enableUDP: true,
		localDNSMode: dnsModeRespectPolicy, sharedDNSMode: dnsModeRespectPolicy,
		localBypassExclude:  []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("10.0.0.0/8")},
		sharedBypassExclude: []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")},
		fakeIPIPv4Prefix:    netip.MustParsePrefix("198.18.0.0/15"),
		fakeIPIPv6Prefix:    netip.MustParsePrefix("fd00::/48"),
	}
	if _, err := i.compileActionPolicy(); err != nil {
		t.Fatal(err)
	}
}

func TestPortActionsExplicitlyEncodeDNSStage(t *testing.T) {
	for _, mode := range []string{dnsModeHijack, dnsModeRespectPolicy, dnsModeOff} {
		var scope commonEBPF.ActionScope
		appendPortDecisions(&scope, nil, mode, true, true)
		if len(scope.DestinationPort) != 2 {
			t.Fatal("missing TCP/UDP actions")
		}
		for _, rule := range scope.DestinationPort {
			if rule.Port != 53 || rule.AfterSelectors != (mode == dnsModeRespectPolicy) {
				t.Fatalf("wrong DNS stage: %+v", rule)
			}
			if (rule.Action == commonEBPF.DecisionPass) != (mode == dnsModeOff) {
				t.Fatalf("wrong DNS action: %+v", rule)
			}
		}
	}
}
