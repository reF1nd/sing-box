//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"net/netip"

	"github.com/sagernet/sing-box/adapter"
	ECommon "github.com/sagernet/sing-box/common/ebpf"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/x/list"
)

func (i *Inbound) startBypassRuleSets() error {
	i.bypassRuleSetAccess.Lock()
	defer i.bypassRuleSetAccess.Unlock()
	if i.bypassRuleSetStarted {
		return nil
	}
	i.bypassRuleSetCallbacks = make([]*list.Element[adapter.RuleSetUpdateCallback], 0, len(i.bypassRuleSet))
	for _, ruleSet := range i.bypassRuleSet {
		ruleSet.IncRef()
		i.bypassRuleSetCallbacks = append(
			i.bypassRuleSetCallbacks,
			ruleSet.RegisterCallback(i.updateBypassRuleSet),
		)
	}
	i.bypassRuleSetStarted = true
	updated, err := i.refreshBypassRuleSetsLocked(true, true, true)
	if err != nil {
		i.stopBypassRuleSetsLocked()
		return err
	}
	if updated {
		i.logDebugBypassCIDRUpdate()
	}
	return nil
}

func (i *Inbound) stopBypassRuleSets() {
	i.bypassRuleSetAccess.Lock()
	defer i.bypassRuleSetAccess.Unlock()
	i.stopBypassRuleSetsLocked()
}

func (i *Inbound) stopBypassRuleSetsLocked() {
	if !i.bypassRuleSetStarted {
		return
	}
	for ruleSetIndex, ruleSet := range i.bypassRuleSet {
		if ruleSetIndex < len(i.bypassRuleSetCallbacks) {
			ruleSet.UnregisterCallback(i.bypassRuleSetCallbacks[ruleSetIndex])
		}
		ruleSet.DecRef()
	}
	i.bypassRuleSetCallbacks = nil
	i.bypassRuleSetPolicy = ECommon.BypassCIDRPolicy{}
	i.bypassRuleSetDirty = false
	i.bypassRuleSetStarted = false
}

func (i *Inbound) updateBypassRuleSet(adapter.RuleSet) {
	i.bypassRuleSetAccess.Lock()
	defer i.bypassRuleSetAccess.Unlock()
	if !i.bypassRuleSetStarted {
		return
	}
	updated, err := i.refreshBypassRuleSetsLocked(true, false, true)
	if err != nil {
		i.policyWarnings.warn(i.logger, "refresh eBPF bypass_rule_set; keeping previous policy: ", err)
		return
	}
	if updated {
		i.logDebugBypassCIDRUpdate()
	}
}

func (i *Inbound) refreshBypassRuleSetsLocked(
	extractRuleSets bool,
	warnEmpty bool,
	warnConflicts bool,
) (bool, error) {
	policy := i.bypassRuleSetPolicy
	if extractRuleSets {
		var ruleSetPrefixes []netip.Prefix
		for _, ruleSet := range i.bypassRuleSet {
			ipSets := ruleSet.ExtractIPSet()
			if warnEmpty && len(ipSets) == 0 {
				i.logger.Warn("bypass_rule_set: no destination IP CIDR rules found in rule-set: ", ruleSet.Name())
			}
			for _, ipSet := range ipSets {
				prefixes := ipSet.Prefixes()
				ruleSetPrefixes = append(ruleSetPrefixes, prefixes...)
			}
		}
		i.logDebugBypassRuleSetExtraction(len(ruleSetPrefixes))
		if conflicts := i.fakeIPBypassConflictCount(ruleSetPrefixes); conflicts > 0 && warnConflicts {
			i.logger.Warn(
				"eBPF FakeIP force interception overrides bypass_rule_set CIDRs: overlaps=",
				conflicts,
			)
		}
		var err error
		policy, err = i.compileBypassCIDRPolicy(ruleSetPrefixes)
		if err != nil {
			return false, err
		}
		i.bypassRuleSetPolicy = policy
		i.bypassRuleSetDirty = true
	}
	updatePolicy := i.bypassRuleSetDirty
	backend := i.cgroupBackendInstance()
	if backend != nil {
		if err := backend.UpdateHostAddresses(i.localInterfaceAddresses()); err != nil {
			return false, err
		}
		if !updatePolicy {
			return false, nil
		}
		updated, err := backend.UpdateCompiledBypassCIDR(policy)
		if err != nil {
			return false, err
		}
		i.bypassRuleSetDirty = false
		if i.sharedNetwork != nil {
			if sharedBackend := i.sharedNetwork.sharedBackendInstance(); sharedBackend != nil {
				ipv4Count, ipv6Count := backend.BypassCIDRCount()
				if err = sharedBackend.SetBypassCIDRState(ipv4Count, ipv6Count); err != nil {
					return false, err
				}
			}
		}
		return updated, nil
	}
	if i.sharedNetwork != nil {
		if sharedBackend := i.sharedNetwork.sharedBackendInstance(); sharedBackend != nil {
			if !updatePolicy {
				return false, nil
			}
			updated, err := sharedBackend.UpdateCompiledBypassCIDR(policy)
			if err != nil {
				return false, err
			}
			i.bypassRuleSetDirty = false
			return updated, nil
		}
	}
	return updatePolicy, nil
}

func (i *Inbound) compileBypassCIDRPolicy(prefixes []netip.Prefix) (ECommon.BypassCIDRPolicy, error) {
	policy, err := ECommon.CompileBypassCIDRPolicy(prefixes)
	if err != nil {
		return policy, E.Cause(err, "compile eBPF bypass CIDR policy")
	}
	return policy, nil
}

func (i *Inbound) localInterfaceAddresses() []netip.Addr {
	prefixes := localInterfacePrefixes(i.networkManager.InterfaceFinder().Interfaces())
	addresses := make([]netip.Addr, len(prefixes))
	for index, prefix := range prefixes {
		addresses[index] = prefix.Addr()
	}
	return addresses
}

func localInterfacePrefixes(interfaces []control.Interface) []netip.Prefix {
	var prefixes []netip.Prefix
	for _, networkInterface := range interfaces {
		for _, prefix := range networkInterface.Addresses {
			if !prefix.IsValid() {
				continue
			}
			address := prefix.Addr().Unmap()
			if address.IsUnspecified() || address.IsLoopback() {
				continue
			}
			prefixes = append(prefixes, netip.PrefixFrom(address, address.BitLen()))
		}
	}
	return prefixes
}

func (i *Inbound) InterfaceUpdated(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	i.udpNat.Purge()
	i.bypassRuleSetAccess.Lock()
	if ctx.Err() != nil {
		i.bypassRuleSetAccess.Unlock()
		return
	}
	if i.bypassRuleSetStarted {
		updated, err := i.refreshBypassRuleSetsLocked(false, false, false)
		if err != nil {
			i.policyWarnings.warn(i.logger, "refresh eBPF local interface bypass; keeping previous policy: ", err)
		} else if updated {
			i.logDebugBypassCIDRUpdate()
		}
	}
	i.bypassRuleSetAccess.Unlock()
	if ctx.Err() != nil {
		return
	}
	i.lifecycleAccess.Lock()
	defer i.lifecycleAccess.Unlock()
	if ctx.Err() != nil {
		return
	}
	if ctx.Err() == nil && i.sharedNetwork != nil {
		i.sharedNetwork.InterfaceUpdated()
	}
}
