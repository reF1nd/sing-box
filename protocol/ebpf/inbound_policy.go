//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net/netip"
	"slices"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/control"
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
	updated, err := i.refreshBypassRuleSetsLocked(true, true)
	if err != nil {
		i.stopBypassRuleSetsLocked()
		return err
	}
	if updated {
		i.logBypassCIDRUpdate()
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
	i.bypassRuleSetStarted = false
}

func (i *Inbound) updateBypassRuleSet(adapter.RuleSet) {
	i.bypassRuleSetAccess.Lock()
	defer i.bypassRuleSetAccess.Unlock()
	if !i.bypassRuleSetStarted {
		return
	}
	updated, err := i.refreshBypassRuleSetsLocked(false, true)
	if err != nil {
		i.logger.Error("refresh eBPF bypass_rule_set: ", err)
		return
	}
	if updated {
		i.logBypassCIDRUpdate()
	}
}

func (i *Inbound) refreshBypassRuleSetsLocked(warnEmpty bool, logRuleSetCount bool) (bool, error) {
	prefixes := i.localInterfacePrefixes()
	for _, ruleSet := range i.bypassRuleSet {
		ipSets := ruleSet.ExtractIPSet()
		if warnEmpty && len(ipSets) == 0 {
			i.logger.Warn("bypass_rule_set: no destination IP CIDR rules found in rule-set: ", ruleSet.Name())
		}
		var cidrCount int
		for _, ipSet := range ipSets {
			ruleSetPrefixes := ipSet.Prefixes()
			prefixes = append(prefixes, ruleSetPrefixes...)
			cidrCount += len(ruleSetPrefixes)
		}
		if logRuleSetCount {
			i.logger.Debug(
				"extracted eBPF bypass CIDRs from rule-set: tag=", ruleSet.Name(),
				", count=", cidrCount,
			)
		}
	}
	backend := i.cgroupBackendInstance()
	if backend != nil {
		updated, err := backend.UpdateBypassCIDR(prefixes)
		if err != nil {
			return false, err
		}
		if i.sharedNetwork != nil {
			if sharedBackend := i.sharedNetwork.sharedBackendInstance(); sharedBackend != nil {
				if err = sharedBackend.SetBypassCIDRState(prefixes); err != nil {
					return false, err
				}
			}
		}
		i.bypassCIDR = slices.Clone(prefixes)
		return updated, nil
	}
	if i.sharedNetwork != nil {
		if sharedBackend := i.sharedNetwork.sharedBackendInstance(); sharedBackend != nil {
			updated, err := sharedBackend.UpdateBypassCIDR(prefixes)
			if err != nil {
				return false, err
			}
			i.bypassCIDR = slices.Clone(prefixes)
			return updated, nil
		}
	}
	updated := !slices.Equal(i.bypassCIDR, prefixes)
	i.bypassCIDR = slices.Clone(prefixes)
	return updated, nil
}

func (i *Inbound) currentBypassCIDR() []netip.Prefix {
	i.bypassRuleSetAccess.Lock()
	defer i.bypassRuleSetAccess.Unlock()
	return slices.Clone(i.bypassCIDR)
}

func (i *Inbound) localInterfacePrefixes() []netip.Prefix {
	return localInterfacePrefixes(i.networkManager.InterfaceFinder().Interfaces())
}

func localInterfacePrefixes(interfaces []control.Interface) []netip.Prefix {
	var prefixes []netip.Prefix
	for _, networkInterface := range interfaces {
		for _, prefix := range networkInterface.Addresses {
			if !prefix.IsValid() {
				continue
			}
			prefix = prefix.Masked()
			address := prefix.Addr().Unmap()
			prefixBits := prefix.Bits()
			if prefix.Addr().Is4In6() {
				if prefixBits < 96 {
					continue
				}
				prefixBits -= 96
			}
			if address.IsUnspecified() || address.IsLoopback() {
				continue
			}
			prefixes = append(prefixes, netip.PrefixFrom(address, prefixBits).Masked())
		}
	}
	return prefixes
}

func (i *Inbound) logBypassCIDRUpdate() {
	var ipv4Count, ipv6Count int
	var countLoaded bool
	backend := i.cgroupBackendInstance()
	if backend != nil {
		ipv4Count, ipv6Count = backend.BypassCIDRCount()
		countLoaded = true
	} else if i.sharedNetwork != nil {
		if sharedBackend := i.sharedNetwork.sharedBackendInstance(); sharedBackend != nil {
			ipv4Count, ipv6Count = sharedBackend.BypassCIDRCount()
			countLoaded = true
		}
	}
	if !countLoaded {
		for _, prefix := range i.bypassCIDR {
			if prefix.Addr().Is4() || prefix.Addr().Is4In6() {
				ipv4Count++
			} else {
				ipv6Count++
			}
		}
	}
	i.logger.Debug("refreshed eBPF bypass CIDR policy: ipv4=", ipv4Count, ", ipv6=", ipv6Count)
}

func (i *Inbound) InterfaceUpdated() {
	i.udpNat.Purge()
	i.bypassRuleSetAccess.Lock()
	if i.bypassRuleSetStarted {
		updated, err := i.refreshBypassRuleSetsLocked(false, false)
		if err != nil {
			i.logger.Error("refresh eBPF local interface bypass: ", err)
		} else if updated {
			i.logBypassCIDRUpdate()
		}
	}
	i.bypassRuleSetAccess.Unlock()
	i.lifecycleAccess.Lock()
	defer i.lifecycleAccess.Unlock()
	if err := i.refreshCgroupIPv6Availability(false); err != nil {
		i.logger.Warn("refresh eBPF local cgroup IPv6 availability: ", err)
	}
	if i.sharedNetwork != nil {
		i.sharedNetwork.InterfaceUpdated()
	}
}
