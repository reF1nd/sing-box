//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net/netip"
	"slices"

	E "github.com/sagernet/sing/common/exceptions"

	CiliumEBPF "github.com/cilium/ebpf"
)

func (b *SharedNetworkBackend) initializeSourceCIDRPolicy(include, exclude dualStackCIDRPrefixes) error {
	var err error
	includeIPv4, includeIPv6 := include.ipv4, include.ipv6
	excludeIPv4, excludeIPv6 := exclude.ipv4, exclude.ipv6
	if err := checkLPMTriePolicyCompatibility(
		"shared-network source CIDR",
		len(includeIPv4)+len(includeIPv6)+len(excludeIPv4)+len(excludeIPv6),
	); err != nil {
		return err
	}
	if b == nil || b.runtime == nil {
		return errBackendClosed
	}
	if _, err = replaceDualStackCIDRPolicy(
		b.runtime.maps["shared_include_source_ipv4"],
		b.runtime.maps["shared_include_source_ipv6"],
		dualStackCIDRPrefixes{},
		dualStackCIDRPrefixes{includeIPv4, includeIPv6},
		"shared-network ",
		"include source CIDR",
	); err != nil {
		return err
	}
	if _, err = replaceDualStackCIDRPolicy(
		b.runtime.maps["shared_exclude_source_ipv4"],
		b.runtime.maps["shared_exclude_source_ipv6"],
		dualStackCIDRPrefixes{},
		dualStackCIDRPrefixes{excludeIPv4, excludeIPv6},
		"shared-network ",
		"exclude source CIDR",
	); err != nil {
		return err
	}
	b.includeSourceIPv4 = includeIPv4
	b.includeSourceIPv6 = includeIPv6
	b.excludeSourceIPv4 = excludeIPv4
	b.excludeSourceIPv6 = excludeIPv6
	return b.updatePolicyFlagsLocked()
}

func (b *SharedNetworkBackend) initializeSourceMACPolicy(include, exclude []MACAddress) error {
	if len(include) > maxSharedSourceMACPolicyEntries || len(exclude) > maxSharedSourceMACPolicyEntries {
		return E.New("shared-network source MAC policy exceeds eBPF map capacity")
	}
	if b == nil || b.runtime == nil {
		return errBackendClosed
	}
	if err := populateSharedNetworkMACPolicy(
		b.runtime.maps["shared_include_source_mac"],
		include,
	); err != nil {
		return E.Cause(err, "populate shared-network include source MAC policy")
	}
	if err := populateSharedNetworkMACPolicy(
		b.runtime.maps["shared_exclude_source_mac"],
		exclude,
	); err != nil {
		return E.Cause(err, "populate shared-network exclude source MAC policy")
	}
	b.includeSourceMAC = slices.Clone(include)
	b.excludeSourceMAC = slices.Clone(exclude)
	return b.updatePolicyFlagsLocked()
}

func populateSharedNetworkMACPolicy(mapInstance *CiliumEBPF.Map, addresses []MACAddress) error {
	if len(addresses) == 0 {
		return nil
	}
	keys := make([]sharedNetworkMACKey, len(addresses))
	values := make([]uint8, len(addresses))
	for index, address := range addresses {
		keys[index] = sharedNetworkMACKey{Address: address}
		values[index] = 1
	}
	_, err := updateMapBatch(mapInstance, keys, values, 0, &sourceMACUpdateBatchSupport)
	return err
}

func (b *SharedNetworkBackend) UpdateCompiledBypassCIDR(policy BypassCIDRPolicy) (bool, error) {
	ipv4 := policy.ipv4
	ipv6 := policy.ipv6
	err := checkLPMTriePolicyCompatibility("shared-network bypass CIDR", len(ipv4)+len(ipv6))
	if err != nil {
		return false, err
	}
	if len(ipv4) > maxBypassCIDRPolicyEntries || len(ipv6) > maxBypassCIDRPolicyEntries {
		return false, E.New("shared-network bypass CIDR policy exceeds eBPF map capacity")
	}
	if b == nil {
		return false, errBackendClosed
	}
	b.access.Lock()
	defer b.access.Unlock()
	if err = b.requireUsableLocked(); err != nil {
		return false, err
	}
	if b.bypassIPv4MapFD < 0 || b.bypassIPv6MapFD < 0 {
		return false, errBackendClosed
	}
	oldPrefixes := dualStackCIDRPrefixes{b.bypassIPv4CIDR, b.bypassIPv6CIDR}
	newPrefixes := dualStackCIDRPrefixes{ipv4, ipv6}
	changed, err := replaceDualStackCIDRPolicy(
		b.bypassIPv4Map,
		b.bypassIPv6Map,
		oldPrefixes,
		newPrefixes,
		"shared-network ",
		"bypass CIDR",
	)
	if err != nil {
		if policyRollbackFailed(err) {
			return false, b.invalidateLocked("bypass CIDR policy", err)
		}
		return false, err
	}
	oldIPv4 := b.bypassIPv4CIDR
	oldIPv6 := b.bypassIPv6CIDR
	oldIPv4Count := b.bypassIPv4Count
	oldIPv6Count := b.bypassIPv6Count
	oldFlags := b.control.Flags
	b.bypassIPv4CIDR = slices.Clone(ipv4)
	b.bypassIPv6CIDR = slices.Clone(ipv6)
	b.bypassIPv4Count = len(ipv4)
	b.bypassIPv6Count = len(ipv6)
	if err = b.updatePolicyFlagsLocked(); err != nil {
		b.bypassIPv4CIDR = oldIPv4
		b.bypassIPv6CIDR = oldIPv6
		b.bypassIPv4Count = oldIPv4Count
		b.bypassIPv6Count = oldIPv6Count
		b.control.Flags = oldFlags
		rollbackErr := rollbackSharedNetworkPolicyMaps(
			b.bypassIPv4Map,
			b.bypassIPv6Map,
			newPrefixes,
			oldPrefixes,
			"bypass CIDR",
		)
		if rollbackErr != nil {
			return false, b.invalidateLocked(
				"bypass CIDR policy",
				E.Errors(err, E.Cause(rollbackErr, "rollback bypass CIDR maps")),
			)
		}
		return false, err
	}
	return changed, nil
}

func (b *SharedNetworkBackend) BypassCIDRCount() (int, int) {
	if b == nil {
		return 0, 0
	}
	b.access.RLock()
	defer b.access.RUnlock()
	return b.bypassIPv4Count, b.bypassIPv6Count
}

func (b *SharedNetworkBackend) UpdateHostAddresses(addresses []netip.Addr) error {
	if b == nil {
		return errBackendClosed
	}
	ipv4, ipv6 := compileHostPrefixes(addresses)
	if len(ipv4) > maxHostAddressPolicyEntries || len(ipv6) > maxHostAddressPolicyEntries {
		return E.New("shared-network host address policy exceeds eBPF map capacity")
	}
	b.access.Lock()
	defer b.access.Unlock()
	if err := b.requireUsableLocked(); err != nil {
		return err
	}
	oldPrefixes := dualStackCIDRPrefixes{b.hostIPv4, b.hostIPv6}
	newPrefixes := dualStackCIDRPrefixes{ipv4, ipv6}
	_, err := replaceDualStackCIDRPolicy(
		b.runtime.maps["shared_host_ipv4"],
		b.runtime.maps["shared_host_ipv6"],
		oldPrefixes,
		newPrefixes,
		"shared-network ",
		"host",
	)
	if err != nil {
		if policyRollbackFailed(err) {
			return b.invalidateLocked("host address policy", err)
		}
		return err
	}
	oldIPv4 := b.hostIPv4
	oldIPv6 := b.hostIPv6
	oldFlags := b.control.Flags
	b.hostIPv4 = ipv4
	b.hostIPv6 = ipv6
	if err = b.updatePolicyFlagsLocked(); err != nil {
		b.hostIPv4 = oldIPv4
		b.hostIPv6 = oldIPv6
		b.control.Flags = oldFlags
		rollbackErr := rollbackSharedNetworkPolicyMaps(
			b.runtime.maps["shared_host_ipv4"],
			b.runtime.maps["shared_host_ipv6"],
			newPrefixes,
			oldPrefixes,
			"host address",
		)
		if rollbackErr != nil {
			return b.invalidateLocked(
				"host address policy",
				E.Errors(err, E.Cause(rollbackErr, "rollback host address maps")),
			)
		}
		return err
	}
	return nil
}

// SetBypassCIDRState updates only policy presence flags when the maps are
// owned by a cgroup backend and shared-network reuses those descriptors.
func (b *SharedNetworkBackend) SetBypassCIDRState(ipv4Count, ipv6Count int) error {
	if b == nil {
		return errBackendClosed
	}
	if ipv4Count < 0 || ipv4Count > maxBypassCIDRPolicyEntries ||
		ipv6Count < 0 || ipv6Count > maxBypassCIDRPolicyEntries {
		return E.New("invalid shared-network bypass CIDR state")
	}
	b.access.Lock()
	defer b.access.Unlock()
	if err := b.requireUsableLocked(); err != nil {
		return err
	}
	oldIPv4Count := b.bypassIPv4Count
	oldIPv6Count := b.bypassIPv6Count
	oldFlags := b.control.Flags
	b.bypassIPv4Count = ipv4Count
	b.bypassIPv6Count = ipv6Count
	if err := b.updatePolicyFlagsLocked(); err != nil {
		b.bypassIPv4Count = oldIPv4Count
		b.bypassIPv6Count = oldIPv6Count
		b.control.Flags = oldFlags
		return err
	}
	return nil
}

func rollbackSharedNetworkPolicyMaps(
	ipv4Map *CiliumEBPF.Map,
	ipv6Map *CiliumEBPF.Map,
	current dualStackCIDRPrefixes,
	previous dualStackCIDRPrefixes,
	policyName string,
) error {
	_, err := replaceDualStackCIDRPolicy(
		ipv4Map,
		ipv6Map,
		current,
		previous,
		"shared-network ",
		policyName,
	)
	return err
}

func (b *SharedNetworkBackend) updatePolicyFlagsLocked() error {
	// Keep cache lookups enabled after policy removal so existing bypass flows
	// retain their decision until the normal TCP/UDP cache lifetime ends.
	bypassFlowCacheFlag := b.control.Flags & sharedNetworkFlagBypassFlowCache
	b.control.Flags &^= sharedNetworkPolicyFlags
	vector := policyVector{
		HostIPv4:         len(b.hostIPv4) != 0,
		HostIPv6:         len(b.hostIPv6) != 0,
		BypassIPv4:       b.bypassIPv4Count != 0,
		BypassIPv6:       b.bypassIPv6Count != 0,
		IncludeSource:    len(b.includeSourceIPv4) != 0 || len(b.includeSourceIPv6) != 0,
		ExcludeSource:    len(b.excludeSourceIPv4) != 0 || len(b.excludeSourceIPv6) != 0,
		IncludeSourceMAC: len(b.includeSourceMAC) != 0,
		ExcludeSourceMAC: len(b.excludeSourceMAC) != 0,
		BypassFlowCache:  bypassFlowCacheFlag != 0,
	}
	policyFlags := vector.sharedFlags() & sharedNetworkPolicyFlags
	if sharedNetworkBypassFlowCacheRequired(policyFlags) {
		policyFlags |= sharedNetworkFlagBypassFlowCache
	}
	b.control.Flags |= policyFlags
	return b.updateControl()
}
