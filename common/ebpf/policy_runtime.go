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

const (
	maxSharedSourceCIDRPolicyEntries = 4096
	maxSharedSourceMACPolicyEntries  = 1024
)

func populatePortPolicyMap(mapInstance *CiliumEBPF.Map, ranges []PortRange, enableTCP, enableUDP bool) error {
	if mapInstance == nil {
		return errBackendClosed
	}
	var entries []tcPortKey
	for _, portRange := range ranges {
		if portRange.Start == 0 || portRange.Start > portRange.End {
			return E.New("invalid TC eBPF port bypass range")
		}
		for port := uint32(portRange.Start); port <= uint32(portRange.End); port++ {
			if enableTCP {
				entries = append(entries, tcPortKey{Protocol: ProtocolTCP, Port: uint16(port)})
			}
			if enableUDP {
				entries = append(entries, tcPortKey{Protocol: ProtocolUDP, Port: uint16(port)})
			}
			if len(entries) > tcPortPolicyCapacity {
				return E.New("TC eBPF port bypass policy exceeds map capacity")
			}
		}
	}
	value := uint8(1)
	for _, entry := range entries {
		if err := mapInstance.Update(&entry, &value, CiliumEBPF.UpdateAny); err != nil {
			return err
		}
	}
	return nil
}

var (
	uidPolicyUpdateBatchSupport  mapBatchSupport
	bypassCIDRUpdateBatchSupport mapBatchSupport
	bypassCIDRDeleteBatchSupport mapBatchSupport
	sourceMACUpdateBatchSupport  mapBatchSupport
)

func populateUIDPolicyMap(mapInstance *CiliumEBPF.Map, entries []uidLPMKey) error {
	if len(entries) == 0 {
		return nil
	}
	values := make([]uint8, len(entries))
	for index := range values {
		values[index] = 1
	}
	_, err := updateMapBatch(mapInstance, entries, values, 0, &uidPolicyUpdateBatchSupport)
	return err
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
		if err := replaceCIDRPolicyMap(ipv6Map, current.ipv6, next.ipv6); err != nil {
			return false, E.Cause(err, "update ", scope, "IPv6 ", policyName, " map")
		}
	}
	if !ipv4Changed {
		return true, nil
	}
	if err := replaceCIDRPolicyMap(ipv4Map, current.ipv4, next.ipv4); err != nil {
		updateErr := E.Cause(err, "update ", scope, "IPv4 ", policyName, " map")
		if ipv6Changed {
			rollbackErr := replaceCIDRPolicyMap(ipv6Map, next.ipv6, current.ipv6)
			if rollbackErr != nil {
				updateErr = policyUpdateError(updateErr, E.Cause(rollbackErr, "rollback ", scope, "IPv6 ", policyName, " map"))
			}
		}
		return false, updateErr
	}
	return true, nil
}

func replaceCIDRPolicyMap(mapInstance *CiliumEBPF.Map, current, next []netip.Prefix) error {
	additions, removals := bypassCIDRPolicyDelta(current, next)
	if len(additions) == 0 && len(removals) == 0 {
		return nil
	}
	if mapInstance == nil {
		return errBackendClosed
	}
	value := uint8(1)
	added := make([]netip.Prefix, 0, len(additions))
	processed, err := updateCIDRMapEntries(mapInstance, additions, bpfNoExist)
	if processed > uint32(len(additions)) {
		return E.New("invalid eBPF batch update count: ", processed)
	}
	added = append(added, additions[:processed]...)
	if err != nil {
		if !errors.Is(err, unix.EEXIST) && !errors.Is(err, CiliumEBPF.ErrKeyExist) {
			return policyUpdateError(err, rollbackCIDRPolicyMap(mapInstance, added, nil))
		}
		for _, prefix := range additions[processed:] {
			err = updateCIDRMapEntry(mapInstance, prefix, &value, bpfNoExist)
			if errors.Is(err, unix.EEXIST) || errors.Is(err, CiliumEBPF.ErrKeyExist) {
				continue
			}
			if err != nil {
				return policyUpdateError(err, rollbackCIDRPolicyMap(mapInstance, added, nil))
			}
			added = append(added, prefix)
		}
	}
	removed := make([]netip.Prefix, 0, len(removals))
	processed, err = deleteCIDRMapEntries(mapInstance, removals)
	if processed > uint32(len(removals)) {
		return E.New("invalid eBPF batch delete count: ", processed)
	}
	removed = append(removed, removals[:processed]...)
	if err != nil {
		if !errors.Is(err, unix.ENOENT) && !errors.Is(err, CiliumEBPF.ErrKeyNotExist) {
			return policyUpdateError(err, rollbackCIDRPolicyMap(mapInstance, added, removed))
		}
		for _, prefix := range removals[processed:] {
			err = deleteCIDRMapEntry(mapInstance, prefix)
			if errors.Is(err, unix.ENOENT) || errors.Is(err, CiliumEBPF.ErrKeyNotExist) {
				continue
			}
			if err != nil {
				return policyUpdateError(err, rollbackCIDRPolicyMap(mapInstance, added, removed))
			}
			removed = append(removed, prefix)
		}
	}
	return nil
}

func updateCIDRMapEntries(mapInstance *CiliumEBPF.Map, prefixes []netip.Prefix, flags uint64) (uint32, error) {
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
		return updateMapBatch(mapInstance, keys, values, flags, &bypassCIDRUpdateBatchSupport)
	}
	keys := make([]ipv6CIDRLPMKey, len(prefixes))
	for index, prefix := range prefixes {
		keys[index] = ipv6CIDRLPMKey{PrefixLength: uint32(prefix.Bits()), Address: prefix.Addr().As16()}
	}
	return updateMapBatch(mapInstance, keys, values, flags, &bypassCIDRUpdateBatchSupport)
}

func deleteCIDRMapEntries(mapInstance *CiliumEBPF.Map, prefixes []netip.Prefix) (uint32, error) {
	if len(prefixes) == 0 {
		return 0, nil
	}
	if prefixes[0].Addr().Is4() {
		keys := make([]ipv4CIDRLPMKey, len(prefixes))
		for index, prefix := range prefixes {
			keys[index] = ipv4CIDRLPMKey{PrefixLength: uint32(prefix.Bits()), Address: prefix.Addr().As4()}
		}
		return deleteMapBatch(mapInstance, keys, &bypassCIDRDeleteBatchSupport)
	}
	keys := make([]ipv6CIDRLPMKey, len(prefixes))
	for index, prefix := range prefixes {
		keys[index] = ipv6CIDRLPMKey{PrefixLength: uint32(prefix.Bits()), Address: prefix.Addr().As16()}
	}
	return deleteMapBatch(mapInstance, keys, &bypassCIDRDeleteBatchSupport)
}

func rollbackCIDRPolicyMap(mapInstance *CiliumEBPF.Map, added, removed []netip.Prefix) error {
	var rollbackErr error
	value := uint8(1)
	for _, prefix := range removed {
		if err := updateCIDRMapEntry(mapInstance, prefix, &value, 0); err != nil {
			rollbackErr = E.Errors(rollbackErr, err)
		}
	}
	for _, prefix := range added {
		if err := deleteCIDRMapEntry(mapInstance, prefix); err != nil &&
			!errors.Is(err, unix.ENOENT) && !errors.Is(err, CiliumEBPF.ErrKeyNotExist) {
			rollbackErr = E.Errors(rollbackErr, err)
		}
	}
	return rollbackErr
}

func updateCIDRMapEntry(mapInstance *CiliumEBPF.Map, prefix netip.Prefix, value *uint8, flags uint64) error {
	if prefix.Addr().Is4() {
		key := ipv4CIDRLPMKey{PrefixLength: uint32(prefix.Bits()), Address: prefix.Addr().As4()}
		return updateMapWithFlags(mapInstance.FD(), unsafe.Pointer(&key), unsafe.Pointer(value), flags)
	}
	key := ipv6CIDRLPMKey{PrefixLength: uint32(prefix.Bits()), Address: prefix.Addr().As16()}
	return updateMapWithFlags(mapInstance.FD(), unsafe.Pointer(&key), unsafe.Pointer(value), flags)
}

func deleteCIDRMapEntry(mapInstance *CiliumEBPF.Map, prefix netip.Prefix) error {
	if prefix.Addr().Is4() {
		key := ipv4CIDRLPMKey{PrefixLength: uint32(prefix.Bits()), Address: prefix.Addr().As4()}
		return deleteMap(mapInstance.FD(), unsafe.Pointer(&key))
	}
	key := ipv6CIDRLPMKey{PrefixLength: uint32(prefix.Bits()), Address: prefix.Addr().As16()}
	return deleteMap(mapInstance.FD(), unsafe.Pointer(&key))
}

func populateSourceMACPolicy(mapInstance *CiliumEBPF.Map, addresses []MACAddress) error {
	if len(addresses) == 0 {
		return nil
	}
	keys := make([]tcMACKey, len(addresses))
	values := make([]uint8, len(addresses))
	for index, address := range addresses {
		keys[index] = tcMACKey{Address: address}
		values[index] = 1
	}
	_, err := updateMapBatch(mapInstance, keys, values, 0, &sourceMACUpdateBatchSupport)
	return err
}

func sourceMACMapCapacity(entries int) uint32 {
	if entries <= 0 {
		return 1
	}
	return uint32(entries)
}

func replaceHostAddressPolicy(
	ipv4Map *CiliumEBPF.Map,
	ipv6Map *CiliumEBPF.Map,
	currentIPv4 [][4]byte,
	currentIPv6 [][16]byte,
	nextIPv4 [][4]byte,
	nextIPv6 [][16]byte,
) error {
	if err := replaceHostAddressMap(ipv4Map, currentIPv4, nextIPv4); err != nil {
		return E.Cause(err, "update TC eBPF IPv4 host addresses")
	}
	if err := replaceHostAddressMap(ipv6Map, currentIPv6, nextIPv6); err != nil {
		rollbackErr := replaceHostAddressMap(ipv4Map, nextIPv4, currentIPv4)
		return E.Errors(
			E.Cause(err, "update TC eBPF IPv6 host addresses"),
			E.Cause(rollbackErr, "rollback TC eBPF IPv4 host addresses"),
		)
	}
	return nil
}

func replaceHostAddressMap[K comparable](mapInstance *CiliumEBPF.Map, current, next []K) error {
	currentSet := make(map[K]struct{}, len(current))
	for _, key := range current {
		currentSet[key] = struct{}{}
	}
	nextSet := make(map[K]struct{}, len(next))
	for _, key := range next {
		nextSet[key] = struct{}{}
	}
	added := make([]K, 0, len(next))
	for _, key := range next {
		if _, loaded := currentSet[key]; !loaded {
			added = append(added, key)
		}
	}
	removed := make([]K, 0, len(current))
	for _, key := range current {
		if _, loaded := nextSet[key]; !loaded {
			removed = append(removed, key)
		}
	}
	value := uint8(1)
	for index, key := range added {
		if err := mapInstance.Update(&key, &value, CiliumEBPF.UpdateAny); err != nil {
			var rollbackErr error
			for _, addedKey := range added[:index] {
				rollbackErr = E.Errors(rollbackErr, mapInstance.Delete(&addedKey))
			}
			return E.Errors(err, E.Cause(rollbackErr, "rollback added host addresses"))
		}
	}
	for index, key := range removed {
		if err := mapInstance.Delete(&key); err != nil &&
			!errors.Is(err, unix.ENOENT) && !errors.Is(err, CiliumEBPF.ErrKeyNotExist) {
			var rollbackErr error
			for _, removedKey := range removed[:index] {
				rollbackErr = E.Errors(rollbackErr, mapInstance.Update(&removedKey, &value, CiliumEBPF.UpdateAny))
			}
			for _, addedKey := range added {
				rollbackErr = E.Errors(rollbackErr, mapInstance.Delete(&addedKey))
			}
			return E.Errors(err, E.Cause(rollbackErr, "rollback host address update"))
		}
	}
	return nil
}
