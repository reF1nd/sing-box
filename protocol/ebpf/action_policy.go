//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net/netip"
	"sort"

	commonEBPF "github.com/CHIZI-0618/sing-ebpf"
	E "github.com/sagernet/sing/common/exceptions"
)

// validateActionPolicyScope keeps data-plane-specific mapping decisions in
// sing-box. These fields have no corresponding map in the selected eBPF
// paths, so silently passing them to sing-ebpf would turn a caller mistake
// into an ignored policy.
func validateActionPolicyScope(policy commonEBPF.ActionPolicy) error {
	if len(policy.Local.SourceCIDR) > 0 || len(policy.Local.SourceMAC) > 0 {
		return E.New("local eBPF action policy does not support source CIDR or MAC decisions")
	}
	if len(policy.Shared.UID) > 0 {
		return E.New("shared eBPF action policy does not support UID decisions")
	}
	return nil
}

// validateBypassExcludeConflicts rejects bypass_exclude prefixes that would
// collide with the fake-ip force-intercept slot. The backend force-intercept
// is a single prefix per address family; fake-ip occupies the same slot, so a
// bypass_exclude prefix for the same family would make the compiled policy
// ambiguous (multiple intercept prefixes) or be silently ignored.
func (i *Inbound) validateBypassExcludeConflicts() error {
	conflict := func(name, family string, bypassExclude, fakeIP netip.Prefix) error {
		if fakeIP.IsValid() && bypassExclude.IsValid() {
			return E.New(name, " bypass_exclude ", bypassExclude, " conflicts with the ", family,
				" fake-ip force-intercept prefix ", fakeIP, "; use redir-host DNS mode or drop one of them")
		}
		return nil
	}
	for _, prefix := range i.localBypassExclude {
		if prefix.Addr().Is4() {
			if err := conflict("local", "IPv4", prefix, i.fakeIPIPv4Prefix); err != nil {
				return err
			}
		} else if err := conflict("local", "IPv6", prefix, i.fakeIPIPv6Prefix); err != nil {
			return err
		}
	}
	for _, prefix := range i.sharedBypassExclude {
		if prefix.Addr().Is4() {
			if err := conflict("shared", "IPv4", prefix, i.fakeIPIPv4Prefix); err != nil {
				return err
			}
		} else if err := conflict("shared", "IPv6", prefix, i.fakeIPIPv6Prefix); err != nil {
			return err
		}
	}
	return nil
}

// compileProcessUIDPolicy converts sing-box's include/exclude/package result
// into final UID actions for sing-ebpf. The library receives no selector
// semantics: unmatched sockets use the returned default action, while each
// decision is the exceptional action to apply to its UID range.
func (i *Inbound) compileProcessUIDPolicy() ([]commonEBPF.UIDDecision, commonEBPF.Decision) {
	if i.localPolicy.IncludeUIDConfigured {
		include := subtractUIDRanges(i.localPolicy.IncludeUID, i.localPolicy.ExcludeUID)
		decisions := make([]commonEBPF.UIDDecision, 0, len(include))
		for _, uid := range include {
			decisions = append(decisions, commonEBPF.UIDDecision{
				Start: uid.Start, End: uid.End, Action: commonEBPF.DecisionIntercept,
			})
		}
		return decisions, commonEBPF.DecisionPass
	}
	decisions := make([]commonEBPF.UIDDecision, 0, len(i.localPolicy.ExcludeUID))
	for _, uid := range i.localPolicy.ExcludeUID {
		decisions = append(decisions, commonEBPF.UIDDecision{
			Start: uid.Start, End: uid.End, Action: commonEBPF.DecisionPass,
		})
	}
	return decisions, commonEBPF.DecisionIntercept
}

func subtractUIDRanges(include, exclude []uidRange) []uidRange {
	if len(include) == 0 {
		return nil
	}
	include = normalizeUIDRanges(include)
	exclude = normalizeUIDRanges(exclude)
	result := make([]uidRange, 0, len(include))
	excludeIndex := 0
	for _, current := range include {
		start, end := uint64(current.Start), uint64(current.End)
		for excludeIndex < len(exclude) && uint64(exclude[excludeIndex].End) < start {
			excludeIndex++
		}
		for index := excludeIndex; index < len(exclude); index++ {
			blocked := exclude[index]
			if uint64(blocked.Start) > end {
				break
			}
			if uint64(blocked.Start) > start {
				result = append(result, uidRange{Start: uint32(start), End: blocked.Start - 1})
			}
			if uint64(blocked.End) >= end {
				start = end + 1
				break
			}
			start = uint64(blocked.End) + 1
		}
		if start <= end {
			result = append(result, uidRange{Start: uint32(start), End: uint32(end)})
		}
	}
	return result
}

func normalizeUIDRanges(ranges []uidRange) []uidRange {
	if len(ranges) == 0 {
		return nil
	}
	normalized := append([]uidRange(nil), ranges...)
	sort.Slice(normalized, func(i, j int) bool {
		if normalized[i].Start != normalized[j].Start {
			return normalized[i].Start < normalized[j].Start
		}
		return normalized[i].End < normalized[j].End
	})
	merged := normalized[:0]
	for _, current := range normalized {
		if len(merged) == 0 {
			merged = append(merged, current)
			continue
		}
		last := &merged[len(merged)-1]
		if current.Start <= last.End || (last.End != ^uint32(0) && current.Start == last.End+1) {
			if current.End > last.End {
				last.End = current.End
			}
			continue
		}
		merged = append(merged, current)
	}
	return merged
}

// eBPFPrivateDestinationPrefixes mirrors the data-plane safety/private ranges
// as final pass decisions. The eBPF library receives only these decisions; it
// does not interpret them as a private-address policy.
var eBPFPrivateDestinationPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("::/128"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

func (i *Inbound) compileActionPolicy() (commonEBPF.CompiledPolicy, error) {
	if err := i.validateBypassExcludeConflicts(); err != nil {
		return commonEBPF.CompiledPolicy{}, err
	}
	policy := commonEBPF.ActionPolicy{
		EnableTCP: i.enableTCP,
		EnableUDP: i.enableUDP,
		Local: commonEBPF.ActionScope{
			Default: commonEBPF.DecisionIntercept,
		},
		Shared: commonEBPF.ActionScope{
			Default: commonEBPF.DecisionIntercept,
		},
	}
	if i.localPolicy.IncludeUIDConfigured {
		policy.Local.Default = commonEBPF.DecisionPass
		for _, uid := range i.localPolicy.IncludeUID {
			policy.Local.UID = append(policy.Local.UID, commonEBPF.UIDDecision{
				Start: uid.Start, End: uid.End, Action: commonEBPF.DecisionIntercept,
			})
		}
	}
	for _, uid := range i.localPolicy.ExcludeUID {
		policy.Local.UID = append(policy.Local.UID, commonEBPF.UIDDecision{
			Start: uid.Start, End: uid.End, Action: commonEBPF.DecisionPass,
		})
	}
	appendDestinationPolicy(&policy.Local, i.localPolicy.BypassPrivateAddress, i.localBypassPort, i.localDNSMode,
		i.fakeIPIPv4Prefix, i.fakeIPIPv6Prefix, i.localBypassExclude, i.enableTCP, i.enableUDP)

	for _, prefix := range i.sharedOptions.IncludeSourceCIDR {
		policy.Shared.SourceCIDR = append(policy.Shared.SourceCIDR, commonEBPF.CIDRDecision{
			Prefix: prefix, Action: commonEBPF.DecisionIntercept,
		})
	}
	for _, prefix := range i.sharedOptions.ExcludeSourceCIDR {
		policy.Shared.SourceCIDR = append(policy.Shared.SourceCIDR, commonEBPF.CIDRDecision{
			Prefix: prefix, Action: commonEBPF.DecisionPass,
		})
	}
	for _, address := range i.sharedIncludeMAC {
		policy.Shared.SourceMAC = append(policy.Shared.SourceMAC, commonEBPF.MACDecision{
			Address: address, Action: commonEBPF.DecisionIntercept,
		})
	}
	for _, address := range i.sharedExcludeMAC {
		policy.Shared.SourceMAC = append(policy.Shared.SourceMAC, commonEBPF.MACDecision{
			Address: address, Action: commonEBPF.DecisionPass,
		})
	}
	appendDestinationPolicy(&policy.Shared, i.sharedBypassPrivate, i.sharedBypassPort, i.sharedDNSMode,
		i.fakeIPIPv4Prefix, i.fakeIPIPv6Prefix, i.sharedBypassExclude, i.enableTCP, i.enableUDP)
	i.localInitialDestinations = destinationPassDecisions(policy.Local.DestinationCIDR)
	i.sharedInitialDestinations = destinationPassDecisions(policy.Shared.DestinationCIDR)
	if err := validateActionPolicyScope(policy); err != nil {
		return commonEBPF.CompiledPolicy{}, err
	}
	return commonEBPF.CompileActionPolicy(policy)
}

func destinationPassDecisions(decisions []commonEBPF.CIDRDecision) []commonEBPF.CIDRDecision {
	result := make([]commonEBPF.CIDRDecision, 0, len(decisions))
	for _, decision := range decisions {
		if decision.Action == commonEBPF.DecisionPass {
			result = append(result, decision)
		}
	}
	return result
}

// appendDestinationPolicy is deliberately shared by local and shared data
// planes. Their steering selectors differ, but private-address, FakeIP,
// bypass_exclude, and destination-port semantics must remain identical when
// the corresponding options are the same.
func appendDestinationPolicy(
	scope *commonEBPF.ActionScope,
	bypassPrivate bool,
	bypassPorts []portRange,
	dnsMode string,
	fakeIPv4, fakeIPv6 netip.Prefix,
	bypassExclude []netip.Prefix,
	enableTCP, enableUDP bool,
) {
	if bypassPrivate {
		for _, prefix := range eBPFPrivateDestinationPrefixes {
			scope.DestinationCIDR = append(scope.DestinationCIDR, commonEBPF.CIDRDecision{
				Prefix: prefix, Action: commonEBPF.DecisionPass,
			})
		}
	}
	for _, prefix := range bypassExclude {
		scope.DestinationCIDR = append(scope.DestinationCIDR, commonEBPF.CIDRDecision{
			Prefix: prefix, Action: commonEBPF.DecisionIntercept,
		})
	}
	if fakeIPv4.IsValid() {
		scope.DestinationCIDR = append(scope.DestinationCIDR, commonEBPF.CIDRDecision{
			Prefix: fakeIPv4, Action: commonEBPF.DecisionIntercept,
		})
	}
	if fakeIPv6.IsValid() {
		scope.DestinationCIDR = append(scope.DestinationCIDR, commonEBPF.CIDRDecision{
			Prefix: fakeIPv6, Action: commonEBPF.DecisionIntercept,
		})
	}
	appendPortDecisions(scope, bypassPorts, dnsMode, enableTCP, enableUDP)
}

func appendPortDecisions(scope *commonEBPF.ActionScope, bypass []portRange, dnsMode string, enableTCP, enableUDP bool) {
	for _, portRange := range bypass {
		for port := portRange.Start; port <= portRange.End; port++ {
			if port == 53 && dnsMode != dnsModeOff {
				continue
			}
			if enableTCP {
				scope.DestinationPort = append(scope.DestinationPort, commonEBPF.PortDecision{
					Protocol: commonEBPF.ProtocolTCP, Port: port, Action: commonEBPF.DecisionPass,
				})
			}
			if enableUDP {
				scope.DestinationPort = append(scope.DestinationPort, commonEBPF.PortDecision{
					Protocol: commonEBPF.ProtocolUDP, Port: port, Action: commonEBPF.DecisionPass,
				})
			}
			if port == portRange.End {
				break
			}
		}
	}
	if dnsMode == dnsModeHijack {
		if enableTCP {
			scope.DestinationPort = append(scope.DestinationPort, commonEBPF.PortDecision{Protocol: commonEBPF.ProtocolTCP, Port: 53, Action: commonEBPF.DecisionIntercept})
		}
		if enableUDP {
			scope.DestinationPort = append(scope.DestinationPort, commonEBPF.PortDecision{Protocol: commonEBPF.ProtocolUDP, Port: 53, Action: commonEBPF.DecisionIntercept})
		}
	} else if dnsMode == dnsModeOff {
		if enableTCP {
			scope.DestinationPort = append(scope.DestinationPort, commonEBPF.PortDecision{Protocol: commonEBPF.ProtocolTCP, Port: 53, Action: commonEBPF.DecisionPass})
		}
		if enableUDP {
			scope.DestinationPort = append(scope.DestinationPort, commonEBPF.PortDecision{Protocol: commonEBPF.ProtocolUDP, Port: 53, Action: commonEBPF.DecisionPass})
		}
	}
}
