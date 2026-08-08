//go:build with_ebpf && (linux || android) && cgo

package ebpf

import (
	"net/netip"
	"slices"
	"unsafe"

	E "github.com/sagernet/sing/common/exceptions"
)

const maxSharedSourceCIDRPolicyEntries = 4096
const maxSharedSourceMACPolicyEntries = 1024

func (b *SharedNetworkBackend) initializeSourceCIDRPolicy(include, exclude []netip.Prefix) error {
	includeIPv4, includeIPv6, err := compileBypassCIDRPolicy(include)
	if err != nil {
		return E.Cause(err, "compile shared-network include source CIDR policy")
	}
	excludeIPv4, excludeIPv6, err := compileBypassCIDRPolicy(exclude)
	if err != nil {
		return E.Cause(err, "compile shared-network exclude source CIDR policy")
	}
	if len(includeIPv4) > maxSharedSourceCIDRPolicyEntries ||
		len(includeIPv6) > maxSharedSourceCIDRPolicyEntries ||
		len(excludeIPv4) > maxSharedSourceCIDRPolicyEntries ||
		len(excludeIPv6) > maxSharedSourceCIDRPolicyEntries {
		return E.New("shared-network source CIDR policy exceeds eBPF map capacity")
	}
	if b == nil || b.runtime == nil {
		return errBackendClosed
	}
	if _, err = replaceDualStackCIDRPolicy(
		int(b.runtime.include_source_ipv4_map_fd),
		int(b.runtime.include_source_ipv6_map_fd),
		dualStackCIDRPrefixes{},
		dualStackCIDRPrefixes{includeIPv4, includeIPv6},
		"shared-network ",
		"include source CIDR",
	); err != nil {
		return err
	}
	if _, err = replaceDualStackCIDRPolicy(
		int(b.runtime.exclude_source_ipv4_map_fd),
		int(b.runtime.exclude_source_ipv6_map_fd),
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
		int(b.runtime.include_source_mac_map_fd),
		include,
	); err != nil {
		return E.Cause(err, "populate shared-network include source MAC policy")
	}
	if err := populateSharedNetworkMACPolicy(
		int(b.runtime.exclude_source_mac_map_fd),
		exclude,
	); err != nil {
		return E.Cause(err, "populate shared-network exclude source MAC policy")
	}
	b.includeSourceMAC = slices.Clone(include)
	b.excludeSourceMAC = slices.Clone(exclude)
	return b.updatePolicyFlagsLocked()
}

func populateSharedNetworkMACPolicy(mapFD int, addresses []MACAddress) error {
	value := uint8(1)
	for _, address := range addresses {
		key := sharedNetworkMACKey{Address: address}
		if err := updateMap(mapFD, unsafe.Pointer(&key), unsafe.Pointer(&value)); err != nil {
			return err
		}
	}
	return nil
}

func (b *SharedNetworkBackend) UpdateBypassCIDR(prefixes []netip.Prefix) (bool, error) {
	ipv4, ipv6, err := compileBypassCIDRPolicy(prefixes)
	if err != nil {
		return false, E.Cause(err, "compile shared-network bypass CIDR policy")
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
		b.bypassIPv4MapFD,
		b.bypassIPv6MapFD,
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
	oldFlags := b.control.Flags
	b.bypassIPv4CIDR = slices.Clone(ipv4)
	b.bypassIPv6CIDR = slices.Clone(ipv6)
	if err = b.updatePolicyFlagsLocked(); err != nil {
		b.bypassIPv4CIDR = oldIPv4
		b.bypassIPv6CIDR = oldIPv6
		b.control.Flags = oldFlags
		rollbackErr := rollbackSharedNetworkPolicyMaps(
			b.bypassIPv4MapFD,
			b.bypassIPv6MapFD,
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
	return len(b.bypassIPv4CIDR), len(b.bypassIPv6CIDR)
}

func (b *SharedNetworkBackend) UpdateHostAddresses(addresses []netip.Addr) error {
	if b == nil {
		return errBackendClosed
	}
	ipv4, ipv6 := compileSharedHostPrefixes(addresses)
	if len(ipv4) > 256 || len(ipv6) > 256 {
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
		int(b.runtime.host_ipv4_map_fd),
		int(b.runtime.host_ipv6_map_fd),
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
			int(b.runtime.host_ipv4_map_fd),
			int(b.runtime.host_ipv6_map_fd),
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
func (b *SharedNetworkBackend) SetBypassCIDRState(prefixes []netip.Prefix) error {
	if b == nil {
		return errBackendClosed
	}
	ipv4, ipv6, err := compileBypassCIDRPolicy(prefixes)
	if err != nil {
		return E.Cause(err, "compile shared-network bypass CIDR state")
	}
	b.access.Lock()
	defer b.access.Unlock()
	if err = b.requireUsableLocked(); err != nil {
		return err
	}
	oldIPv4 := b.bypassIPv4CIDR
	oldIPv6 := b.bypassIPv6CIDR
	oldFlags := b.control.Flags
	b.bypassIPv4CIDR = slices.Clone(ipv4)
	b.bypassIPv6CIDR = slices.Clone(ipv6)
	if err = b.updatePolicyFlagsLocked(); err != nil {
		b.bypassIPv4CIDR = oldIPv4
		b.bypassIPv6CIDR = oldIPv6
		b.control.Flags = oldFlags
	}
	return err
}

func rollbackSharedNetworkPolicyMaps(
	ipv4MapFD int,
	ipv6MapFD int,
	current dualStackCIDRPrefixes,
	previous dualStackCIDRPrefixes,
	policyName string,
) error {
	_, err := replaceDualStackCIDRPolicy(
		ipv4MapFD,
		ipv6MapFD,
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
	b.control.Flags |= bypassFlowCacheFlag
	if len(b.hostIPv4) != 0 {
		b.control.Flags |= sharedNetworkFlagHostIPv4
	}
	if len(b.hostIPv6) != 0 {
		b.control.Flags |= sharedNetworkFlagHostIPv6
	}
	if len(b.bypassIPv4CIDR) != 0 {
		b.control.Flags |= sharedNetworkFlagBypassIPv4
	}
	if len(b.bypassIPv6CIDR) != 0 {
		b.control.Flags |= sharedNetworkFlagBypassIPv6
	}
	if len(b.includeSourceIPv4) != 0 || len(b.includeSourceIPv6) != 0 {
		b.control.Flags |= sharedNetworkFlagIncludeSource
	}
	if len(b.excludeSourceIPv4) != 0 || len(b.excludeSourceIPv6) != 0 {
		b.control.Flags |= sharedNetworkFlagExcludeSource
	}
	if len(b.includeSourceMAC) != 0 {
		b.control.Flags |= sharedNetworkFlagIncludeSourceMAC
	}
	if len(b.excludeSourceMAC) != 0 {
		b.control.Flags |= sharedNetworkFlagExcludeSourceMAC
	}
	if sharedNetworkBypassFlowCacheRequired(b.control.Flags) {
		b.control.Flags |= sharedNetworkFlagBypassFlowCache
	}
	return b.updateControl()
}
