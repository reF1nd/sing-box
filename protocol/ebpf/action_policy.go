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
	if i.localPolicy.BypassPrivateAddress {
		for _, prefix := range eBPFPrivateDestinationPrefixes {
			policy.Local.DestinationCIDR = append(policy.Local.DestinationCIDR, commonEBPF.CIDRDecision{
				Prefix: prefix, Action: commonEBPF.DecisionPass,
			})
		}
	}
	if i.fakeIPIPv4Prefix.IsValid() {
		policy.Local.DestinationCIDR = append(policy.Local.DestinationCIDR, commonEBPF.CIDRDecision{
			Prefix: i.fakeIPIPv4Prefix, Action: commonEBPF.DecisionIntercept,
		})
	}
	if i.fakeIPIPv6Prefix.IsValid() {
		policy.Local.DestinationCIDR = append(policy.Local.DestinationCIDR, commonEBPF.CIDRDecision{
			Prefix: i.fakeIPIPv6Prefix, Action: commonEBPF.DecisionIntercept,
		})
	}
	appendPortDecisions(&policy.Local, i.localBypassPort, i.localDNSMode, i.enableTCP, i.enableUDP)

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
	if i.sharedBypassPrivate {
		for _, prefix := range eBPFPrivateDestinationPrefixes {
			policy.Shared.DestinationCIDR = append(policy.Shared.DestinationCIDR, commonEBPF.CIDRDecision{
				Prefix: prefix, Action: commonEBPF.DecisionPass,
			})
		}
	}
	if i.fakeIPIPv4Prefix.IsValid() {
		policy.Shared.DestinationCIDR = append(policy.Shared.DestinationCIDR, commonEBPF.CIDRDecision{
			Prefix: i.fakeIPIPv4Prefix, Action: commonEBPF.DecisionIntercept,
		})
	}
	if i.fakeIPIPv6Prefix.IsValid() {
		policy.Shared.DestinationCIDR = append(policy.Shared.DestinationCIDR, commonEBPF.CIDRDecision{
			Prefix: i.fakeIPIPv6Prefix, Action: commonEBPF.DecisionIntercept,
		})
	}
	appendPortDecisions(&policy.Shared, i.sharedBypassPort, i.sharedDNSMode, i.enableTCP, i.enableUDP)
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
