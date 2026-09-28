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

func TestValidateActionPolicyScope(t *testing.T) {
	tests := []struct {
		name   string
		local  commonEBPF.ActionScope
		shared commonEBPF.ActionScope
	}{
		{
			name:  "local source CIDR",
			local: commonEBPF.ActionScope{SourceCIDR: []commonEBPF.CIDRDecision{{Prefix: netip.MustParsePrefix("192.0.2.0/24"), Action: commonEBPF.DecisionPass}}},
		},
		{
			name:  "local source MAC",
			local: commonEBPF.ActionScope{SourceMAC: []commonEBPF.MACDecision{{Address: commonEBPF.MACAddress{2, 0, 0, 0, 0, 1}, Action: commonEBPF.DecisionPass}}},
		},
		{
			name:   "shared UID",
			shared: commonEBPF.ActionScope{UID: []commonEBPF.UIDDecision{{Start: 1000, End: 1000, Action: commonEBPF.DecisionPass}}},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := validateActionPolicyScope(commonEBPF.ActionPolicy{Local: test.local, Shared: test.shared}); err == nil {
				t.Fatal("unsupported action scope was accepted")
			}
		})
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
	if got, err := normalizeBypassExclude("local.bypass_exclude", []netip.Prefix{v4, v6}); err != nil || len(got) != 2 {
		t.Fatalf("valid v4+v6 rejected: %v, %v", got, err)
	}
	if _, err := normalizeBypassExclude("local.bypass_exclude", []netip.Prefix{v4, netip.MustParsePrefix("10.0.0.0/8")}); err == nil {
		t.Fatal("two IPv4 prefixes accepted")
	}
	if _, err := normalizeBypassExclude("local.bypass_exclude", []netip.Prefix{v6, netip.MustParsePrefix("fd00::/8")}); err == nil {
		t.Fatal("two IPv6 prefixes accepted")
	}
	// IPv4-mapped IPv6 is converted to its IPv4 form, not rejected outright.
	mapped, err := normalizeBypassExclude("local.bypass_exclude", []netip.Prefix{netip.MustParsePrefix("::ffff:100.64.0.0/104")})
	if err != nil || len(mapped) != 1 || mapped[0].String() != "100.0.0.0/8" {
		t.Fatalf("IPv4-mapped IPv6 not converted to IPv4: %v, %v", mapped, err)
	}
	if got, err := normalizeBypassExclude("local.bypass_exclude", nil); err != nil || got != nil {
		t.Fatalf("empty input: got %v, %v", got, err)
	}
}

func TestValidateBypassExcludeConflicts(t *testing.T) {
	i := &Inbound{
		localBypassExclude:  []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10")},
		sharedBypassExclude: []netip.Prefix{netip.MustParsePrefix("fd7a:115c:a1e0::/48")},
	}
	if err := i.validateBypassExcludeConflicts(); err != nil {
		t.Fatal(err)
	}
	i.fakeIPIPv4Prefix = netip.MustParsePrefix("198.18.0.0/16")
	if err := i.validateBypassExcludeConflicts(); err == nil {
		t.Fatal("fakeip IPv4 conflict accepted")
	}
	i.fakeIPIPv4Prefix = netip.Prefix{}
	i.fakeIPIPv6Prefix = netip.MustParsePrefix("fdfe:dcba:9876::/64")
	if err := i.validateBypassExcludeConflicts(); err == nil {
		t.Fatal("fakeip IPv6 conflict accepted")
	}
}
