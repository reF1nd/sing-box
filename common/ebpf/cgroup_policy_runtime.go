//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"net/netip"
	"slices"
	"unsafe"

	E "github.com/sagernet/sing/common/exceptions"

	CiliumEBPF "github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

var (
	uidPolicyUpdateBatchSupport  mapBatchSupport
	bypassCIDRUpdateBatchSupport mapBatchSupport
	bypassCIDRDeleteBatchSupport mapBatchSupport
)

func validateCgroupMapCapacity(capacity CgroupMapCapacity) error {
	for _, entry := range []struct {
		name  string
		value uint32
	}{
		{"tcp_redirect", capacity.TCPRedirect},
		{"udp_redirect", capacity.UDPRedirect},
		{"udp_peer", capacity.UDPPeer},
		{"udp_flow", capacity.UDPFlow},
		{"socket_bypass", capacity.SocketBypass},
	} {
		if err := validateMapCapacity("eBPF "+entry.name, entry.value); err != nil {
			return err
		}
	}
	return nil
}

func populateUIDPolicyMap(mapInstance *CiliumEBPF.Map, entries []uidLPMKey) error {
	if len(entries) == 0 {
		return nil
	}
	values := make([]uint8, len(entries))
	for index := range values {
		values[index] = 1
	}
	_, err := updateMapBatch(
		mapInstance,
		entries,
		values,
		0,
		&uidPolicyUpdateBatchSupport,
	)
	return err
}

func (b *CgroupBackend) UpdateCompiledBypassCIDR(policy BypassCIDRPolicy) (bool, error) {
	ipv4Prefixes := policy.ipv4
	ipv6Prefixes := policy.ipv6
	err := checkLPMTriePolicyCompatibility("bypass CIDR", len(ipv4Prefixes)+len(ipv6Prefixes))
	if err != nil {
		return false, err
	}
	if len(ipv4Prefixes) > maxBypassCIDRPolicyEntries {
		return false, E.New("IPv4 bypass CIDR policy has too many eBPF map entries: ",
			len(ipv4Prefixes), " > ", maxBypassCIDRPolicyEntries)
	}
	if len(ipv6Prefixes) > maxBypassCIDRPolicyEntries {
		return false, E.New("IPv6 bypass CIDR policy has too many eBPF map entries: ",
			len(ipv6Prefixes), " > ", maxBypassCIDRPolicyEntries)
	}
	if b == nil {
		return false, errBackendClosed
	}
	b.access.Lock()
	defer b.access.Unlock()
	if err = b.health.requireUsable(b.runtime != nil); err != nil {
		return false, err
	}
	if b.bypassIPv4CIDRMapFD < 0 {
		ipv4Prefixes = nil
	}
	if b.bypassIPv6CIDRMapFD < 0 {
		ipv6Prefixes = nil
	}
	changed, err := replaceDualStackCIDRPolicy(
		b.runtime.maps["cgroup_bypass_ipv4"],
		b.runtime.maps["cgroup_bypass_ipv6"],
		dualStackCIDRPrefixes{b.bypassIPv4CIDR, b.bypassIPv6CIDR},
		dualStackCIDRPrefixes{ipv4Prefixes, ipv6Prefixes},
		"",
		"bypass CIDR eBPF",
	)
	if err != nil {
		if policyRollbackFailed(err) {
			return false, E.Errors(err, b.health.invalidate("cgroup", "bypass CIDR policy"))
		}
		return false, err
	}
	b.bypassIPv4CIDR = slices.Clone(ipv4Prefixes)
	b.bypassIPv6CIDR = slices.Clone(ipv6Prefixes)
	return changed, nil
}

func (b *CgroupBackend) BypassCIDRCount() (int, int) {
	if b == nil {
		return 0, 0
	}
	b.access.RLock()
	defer b.access.RUnlock()
	return len(b.bypassIPv4CIDR), len(b.bypassIPv6CIDR)
}

func (b *CgroupBackend) UpdateHostAddresses(addresses []netip.Addr) error {
	if b == nil {
		return errBackendClosed
	}
	ipv4, ipv6 := compileHostPrefixes(addresses)
	if len(ipv4) > maxHostAddressPolicyEntries || len(ipv6) > maxHostAddressPolicyEntries {
		return E.New("local cgroup host address policy exceeds eBPF map capacity")
	}
	b.access.Lock()
	defer b.access.Unlock()
	if err := b.health.requireUsable(b.runtime != nil); err != nil {
		return err
	}
	oldPrefixes := dualStackCIDRPrefixes{b.hostIPv4, b.hostIPv6}
	newPrefixes := dualStackCIDRPrefixes{ipv4, ipv6}
	_, err := replaceDualStackCIDRPolicy(
		b.runtime.maps["cgroup_host_ipv4"],
		b.runtime.maps["cgroup_host_ipv6"],
		oldPrefixes,
		newPrefixes,
		"local cgroup ",
		"host address",
	)
	if err != nil {
		if policyRollbackFailed(err) {
			return E.Errors(err, b.health.invalidate("cgroup", "host address policy"))
		}
		return err
	}
	b.hostIPv4 = slices.Clone(ipv4)
	b.hostIPv6 = slices.Clone(ipv6)
	return nil
}

type dualStackCIDRPrefixes struct {
	ipv4 []netip.Prefix
	ipv6 []netip.Prefix
}

func replaceDualStackCIDRPolicy(
	ipv4Map *CiliumEBPF.Map,
	ipv6Map *CiliumEBPF.Map,
	current dualStackCIDRPrefixes,
	next dualStackCIDRPrefixes,
	scope string,
	policyName string,
) (bool, error) {
	ipv4Changed := !slices.Equal(current.ipv4, next.ipv4)
	ipv6Changed := !slices.Equal(current.ipv6, next.ipv6)
	if !ipv4Changed && !ipv6Changed {
		return false, nil
	}
	if ipv6Changed {
		if err := replaceBypassCIDRPolicyMap(ipv6Map, current.ipv6, next.ipv6); err != nil {
			return false, E.Cause(err, "update ", scope, "IPv6 ", policyName, " map")
		}
	}
	if !ipv4Changed {
		return true, nil
	}
	if err := replaceBypassCIDRPolicyMap(ipv4Map, current.ipv4, next.ipv4); err != nil {
		updateErr := E.Cause(err, "update ", scope, "IPv4 ", policyName, " map")
		if ipv6Changed {
			rollbackErr := replaceBypassCIDRPolicyMap(ipv6Map, next.ipv6, current.ipv6)
			if rollbackErr != nil {
				updateErr = policyUpdateError(
					updateErr,
					E.Cause(rollbackErr, "rollback ", scope, "IPv6 ", policyName, " map"),
				)
			}
		}
		return false, updateErr
	}
	return true, nil
}

func replaceBypassCIDRPolicyMap(
	mapInstance *CiliumEBPF.Map,
	currentPrefixes []netip.Prefix,
	nextPrefixes []netip.Prefix,
) error {
	additions, removals := bypassCIDRPolicyDelta(currentPrefixes, nextPrefixes)
	if len(additions) == 0 && len(removals) == 0 {
		return nil
	}
	if mapInstance == nil {
		return errBackendClosed
	}
	value := uint8(1)
	added := make([]netip.Prefix, 0, len(additions))
	processed, err := updateBypassCIDRMapEntries(mapInstance, additions, bpfNoExist)
	if processed > uint32(len(additions)) {
		return E.New("invalid eBPF batch update count: ", processed)
	}
	added = append(added, additions[:processed]...)
	if err != nil {
		if !errors.Is(err, unix.EEXIST) && !errors.Is(err, CiliumEBPF.ErrKeyExist) {
			return policyUpdateError(err, rollbackBypassCIDRPolicyMap(mapInstance, added, nil))
		}
		for _, prefix := range additions[processed:] {
			err = updateBypassCIDRMapEntry(mapInstance, prefix, &value, bpfNoExist)
			if errors.Is(err, unix.EEXIST) || errors.Is(err, CiliumEBPF.ErrKeyExist) {
				continue
			}
			if err != nil {
				return policyUpdateError(err, rollbackBypassCIDRPolicyMap(mapInstance, added, nil))
			}
			added = append(added, prefix)
		}
	}
	removed := make([]netip.Prefix, 0, len(removals))
	processed, err = deleteBypassCIDRMapEntries(mapInstance, removals)
	if processed > uint32(len(removals)) {
		return E.New("invalid eBPF batch delete count: ", processed)
	}
	removed = append(removed, removals[:processed]...)
	if err != nil {
		if !errors.Is(err, unix.ENOENT) && !errors.Is(err, CiliumEBPF.ErrKeyNotExist) {
			return policyUpdateError(err, rollbackBypassCIDRPolicyMap(mapInstance, added, removed))
		}
		for _, prefix := range removals[processed:] {
			err = deleteBypassCIDRMapEntry(mapInstance, prefix)
			if errors.Is(err, unix.ENOENT) || errors.Is(err, CiliumEBPF.ErrKeyNotExist) {
				continue
			}
			if err != nil {
				return policyUpdateError(err, rollbackBypassCIDRPolicyMap(mapInstance, added, removed))
			}
			removed = append(removed, prefix)
		}
	}
	return nil
}

func updateBypassCIDRMapEntries(mapInstance *CiliumEBPF.Map, prefixes []netip.Prefix, flags uint64) (uint32, error) {
	if len(prefixes) == 0 {
		return 0, nil
	}
	values := make([]uint8, len(prefixes))
	for index := range values {
		values[index] = 1
	}
	if prefixes[0].Addr().Is4() {
		keys := make([]ipv4CIDRLPMKey, len(prefixes))
		for index, prefix := range prefixes {
			keys[index] = ipv4CIDRLPMKey{PrefixLength: uint32(prefix.Bits()), Address: prefix.Addr().As4()}
		}
		return updateMapBatch(
			mapInstance,
			keys,
			values,
			flags,
			&bypassCIDRUpdateBatchSupport,
		)
	}
	keys := make([]ipv6CIDRLPMKey, len(prefixes))
	for index, prefix := range prefixes {
		keys[index] = ipv6CIDRLPMKey{PrefixLength: uint32(prefix.Bits()), Address: prefix.Addr().As16()}
	}
	return updateMapBatch(
		mapInstance,
		keys,
		values,
		flags,
		&bypassCIDRUpdateBatchSupport,
	)
}

func deleteBypassCIDRMapEntries(mapInstance *CiliumEBPF.Map, prefixes []netip.Prefix) (uint32, error) {
	if len(prefixes) == 0 {
		return 0, nil
	}
	if prefixes[0].Addr().Is4() {
		keys := make([]ipv4CIDRLPMKey, len(prefixes))
		for index, prefix := range prefixes {
			keys[index] = ipv4CIDRLPMKey{PrefixLength: uint32(prefix.Bits()), Address: prefix.Addr().As4()}
		}
		return deleteMapBatch(
			mapInstance,
			keys,
			&bypassCIDRDeleteBatchSupport,
		)
	}
	keys := make([]ipv6CIDRLPMKey, len(prefixes))
	for index, prefix := range prefixes {
		keys[index] = ipv6CIDRLPMKey{PrefixLength: uint32(prefix.Bits()), Address: prefix.Addr().As16()}
	}
	return deleteMapBatch(
		mapInstance,
		keys,
		&bypassCIDRDeleteBatchSupport,
	)
}

func rollbackBypassCIDRPolicyMap(mapInstance *CiliumEBPF.Map, added []netip.Prefix, removed []netip.Prefix) error {
	var rollbackErr error
	value := uint8(1)
	for _, prefix := range removed {
		if err := updateBypassCIDRMapEntry(mapInstance, prefix, &value, 0); err != nil {
			rollbackErr = E.Errors(rollbackErr, err)
		}
	}
	for _, prefix := range added {
		if err := deleteBypassCIDRMapEntry(mapInstance, prefix); err != nil &&
			!errors.Is(err, unix.ENOENT) && !errors.Is(err, CiliumEBPF.ErrKeyNotExist) {
			rollbackErr = E.Errors(rollbackErr, err)
		}
	}
	return rollbackErr
}

func updateBypassCIDRMapEntry(mapInstance *CiliumEBPF.Map, prefix netip.Prefix, value *uint8, flags uint64) error {
	mapFD := mapInstance.FD()
	if prefix.Addr().Is4() {
		key := ipv4CIDRLPMKey{PrefixLength: uint32(prefix.Bits()), Address: prefix.Addr().As4()}
		return updateMapWithFlags(mapFD, unsafe.Pointer(&key), unsafe.Pointer(value), flags)
	}
	key := ipv6CIDRLPMKey{PrefixLength: uint32(prefix.Bits()), Address: prefix.Addr().As16()}
	return updateMapWithFlags(mapFD, unsafe.Pointer(&key), unsafe.Pointer(value), flags)
}

func deleteBypassCIDRMapEntry(mapInstance *CiliumEBPF.Map, prefix netip.Prefix) error {
	mapFD := mapInstance.FD()
	if prefix.Addr().Is4() {
		key := ipv4CIDRLPMKey{PrefixLength: uint32(prefix.Bits()), Address: prefix.Addr().As4()}
		return deleteMap(mapFD, unsafe.Pointer(&key))
	}
	key := ipv6CIDRLPMKey{PrefixLength: uint32(prefix.Bits()), Address: prefix.Addr().As16()}
	return deleteMap(mapFD, unsafe.Pointer(&key))
}
