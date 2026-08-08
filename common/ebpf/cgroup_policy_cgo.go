//go:build with_ebpf && (linux || android) && cgo

package ebpf

import (
	"errors"
	"net/netip"
	"slices"
	"unsafe"

	E "github.com/sagernet/sing/common/exceptions"

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
		{"socket_bypass", capacity.SocketBypass},
	} {
		if err := validateMapCapacity("eBPF "+entry.name, entry.value); err != nil {
			return err
		}
	}
	return nil
}

func populateUIDPolicyMap(mapFD int, entries []uidLPMKey) error {
	if len(entries) == 0 {
		return nil
	}
	values := make([]uint8, len(entries))
	for index := range values {
		values[index] = 1
	}
	_, err := updateMapBatch(
		mapFD,
		unsafe.Pointer(&entries[0]),
		unsafe.Pointer(&values[0]),
		uint32(len(entries)),
		unsafe.Sizeof(entries[0]),
		unsafe.Sizeof(values[0]),
		0,
		&uidPolicyUpdateBatchSupport,
	)
	return err
}

func (b *CgroupBackend) UpdateBypassCIDR(prefixes []netip.Prefix) (bool, error) {
	ipv4Prefixes, ipv6Prefixes, err := compileBypassCIDRPolicy(prefixes)
	if err != nil {
		return false, E.Cause(err, "compile bypass CIDR policy")
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
		b.bypassIPv4CIDRMapFD,
		b.bypassIPv6CIDRMapFD,
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

type dualStackCIDRPrefixes struct {
	ipv4 []netip.Prefix
	ipv6 []netip.Prefix
}

func replaceDualStackCIDRPolicy(
	ipv4MapFD int,
	ipv6MapFD int,
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
		if err := replaceBypassCIDRPolicyMap(ipv6MapFD, current.ipv6, next.ipv6); err != nil {
			return false, E.Cause(err, "update ", scope, "IPv6 ", policyName, " map")
		}
	}
	if !ipv4Changed {
		return true, nil
	}
	if err := replaceBypassCIDRPolicyMap(ipv4MapFD, current.ipv4, next.ipv4); err != nil {
		updateErr := E.Cause(err, "update ", scope, "IPv4 ", policyName, " map")
		if ipv6Changed {
			rollbackErr := replaceBypassCIDRPolicyMap(ipv6MapFD, next.ipv6, current.ipv6)
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
	mapFD int,
	currentPrefixes []netip.Prefix,
	nextPrefixes []netip.Prefix,
) error {
	additions, removals := bypassCIDRPolicyDelta(currentPrefixes, nextPrefixes)
	if len(additions) == 0 && len(removals) == 0 {
		return nil
	}
	if mapFD < 0 {
		return errBackendClosed
	}
	value := uint8(1)
	added := make([]netip.Prefix, 0, len(additions))
	processed, err := updateBypassCIDRMapEntries(mapFD, additions, bpfNoExist)
	if processed > uint32(len(additions)) {
		return E.New("invalid eBPF batch update count: ", processed)
	}
	added = append(added, additions[:processed]...)
	if err != nil {
		if !errors.Is(err, unix.EEXIST) {
			return policyUpdateError(err, rollbackBypassCIDRPolicyMap(mapFD, added, nil))
		}
		for _, prefix := range additions[processed:] {
			err = updateBypassCIDRMapEntry(mapFD, prefix, &value, bpfNoExist)
			if errors.Is(err, unix.EEXIST) {
				continue
			}
			if err != nil {
				return policyUpdateError(err, rollbackBypassCIDRPolicyMap(mapFD, added, nil))
			}
			added = append(added, prefix)
		}
	}
	removed := make([]netip.Prefix, 0, len(removals))
	processed, err = deleteBypassCIDRMapEntries(mapFD, removals)
	if processed > uint32(len(removals)) {
		return E.New("invalid eBPF batch delete count: ", processed)
	}
	removed = append(removed, removals[:processed]...)
	if err != nil {
		if !errors.Is(err, unix.ENOENT) {
			return policyUpdateError(err, rollbackBypassCIDRPolicyMap(mapFD, added, removed))
		}
		for _, prefix := range removals[processed:] {
			err = deleteBypassCIDRMapEntry(mapFD, prefix)
			if errors.Is(err, unix.ENOENT) {
				continue
			}
			if err != nil {
				return policyUpdateError(err, rollbackBypassCIDRPolicyMap(mapFD, added, removed))
			}
			removed = append(removed, prefix)
		}
	}
	return nil
}

func updateBypassCIDRMapEntries(mapFD int, prefixes []netip.Prefix, flags uint64) (uint32, error) {
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
			mapFD,
			unsafe.Pointer(&keys[0]),
			unsafe.Pointer(&values[0]),
			uint32(len(keys)),
			unsafe.Sizeof(keys[0]),
			unsafe.Sizeof(values[0]),
			flags,
			&bypassCIDRUpdateBatchSupport,
		)
	}
	keys := make([]ipv6CIDRLPMKey, len(prefixes))
	for index, prefix := range prefixes {
		keys[index] = ipv6CIDRLPMKey{PrefixLength: uint32(prefix.Bits()), Address: prefix.Addr().As16()}
	}
	return updateMapBatch(
		mapFD,
		unsafe.Pointer(&keys[0]),
		unsafe.Pointer(&values[0]),
		uint32(len(keys)),
		unsafe.Sizeof(keys[0]),
		unsafe.Sizeof(values[0]),
		flags,
		&bypassCIDRUpdateBatchSupport,
	)
}

func deleteBypassCIDRMapEntries(mapFD int, prefixes []netip.Prefix) (uint32, error) {
	if len(prefixes) == 0 {
		return 0, nil
	}
	if prefixes[0].Addr().Is4() {
		keys := make([]ipv4CIDRLPMKey, len(prefixes))
		for index, prefix := range prefixes {
			keys[index] = ipv4CIDRLPMKey{PrefixLength: uint32(prefix.Bits()), Address: prefix.Addr().As4()}
		}
		return deleteMapBatch(
			mapFD,
			unsafe.Pointer(&keys[0]),
			uint32(len(keys)),
			unsafe.Sizeof(keys[0]),
			&bypassCIDRDeleteBatchSupport,
		)
	}
	keys := make([]ipv6CIDRLPMKey, len(prefixes))
	for index, prefix := range prefixes {
		keys[index] = ipv6CIDRLPMKey{PrefixLength: uint32(prefix.Bits()), Address: prefix.Addr().As16()}
	}
	return deleteMapBatch(
		mapFD,
		unsafe.Pointer(&keys[0]),
		uint32(len(keys)),
		unsafe.Sizeof(keys[0]),
		&bypassCIDRDeleteBatchSupport,
	)
}

func rollbackBypassCIDRPolicyMap(mapFD int, added []netip.Prefix, removed []netip.Prefix) error {
	var rollbackErr error
	value := uint8(1)
	for _, prefix := range removed {
		if err := updateBypassCIDRMapEntry(mapFD, prefix, &value, 0); err != nil {
			rollbackErr = E.Errors(rollbackErr, err)
		}
	}
	for _, prefix := range added {
		if err := deleteBypassCIDRMapEntry(mapFD, prefix); err != nil && !errors.Is(err, unix.ENOENT) {
			rollbackErr = E.Errors(rollbackErr, err)
		}
	}
	return rollbackErr
}

func updateBypassCIDRMapEntry(mapFD int, prefix netip.Prefix, value *uint8, flags uint64) error {
	if prefix.Addr().Is4() {
		key := ipv4CIDRLPMKey{PrefixLength: uint32(prefix.Bits()), Address: prefix.Addr().As4()}
		return updateMapWithFlags(mapFD, unsafe.Pointer(&key), unsafe.Pointer(value), flags)
	}
	key := ipv6CIDRLPMKey{PrefixLength: uint32(prefix.Bits()), Address: prefix.Addr().As16()}
	return updateMapWithFlags(mapFD, unsafe.Pointer(&key), unsafe.Pointer(value), flags)
}

func deleteBypassCIDRMapEntry(mapFD int, prefix netip.Prefix) error {
	if prefix.Addr().Is4() {
		key := ipv4CIDRLPMKey{PrefixLength: uint32(prefix.Bits()), Address: prefix.Addr().As4()}
		return deleteMap(mapFD, unsafe.Pointer(&key))
	}
	key := ipv6CIDRLPMKey{PrefixLength: uint32(prefix.Bits()), Address: prefix.Addr().As16()}
	return deleteMap(mapFD, unsafe.Pointer(&key))
}
