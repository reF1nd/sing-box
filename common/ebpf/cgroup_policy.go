//go:build with_ebpf && (linux || android)

package ebpf

import (
	"encoding/binary"
	"math/bits"
	"net/netip"
	"sort"

	"go4.org/netipx"
)

const (
	maxUIDPolicyEntries        = 4096
	maxBypassCIDRPolicyEntries = 65536
)

type CgroupPolicy struct {
	EnableBypassCIDR bool
	HijackDNS        bool
	IncludeUID       []UIDRange
	ExcludeUID       []UIDRange
}

type UIDRange struct {
	Start uint32
	End   uint32
}

type uidLPMKey struct {
	PrefixLength uint32
	UID          [4]byte
}

type ipv4CIDRLPMKey struct {
	PrefixLength uint32
	Address      [4]byte
}

type ipv6CIDRLPMKey struct {
	PrefixLength uint32
	Address      [16]byte
}

func compileUIDRanges(uidRanges []UIDRange) []uidLPMKey {
	entries := make(map[uidLPMKey]struct{})
	for _, uidRange := range uidRanges {
		start := uint64(uidRange.Start)
		end := uint64(uidRange.End)
		for start <= end {
			var blockSize uint64
			if start == 0 {
				blockSize = uint64(1) << 32
			} else {
				blockSize = uint64(1) << bits.TrailingZeros64(start)
			}
			remaining := end - start + 1
			for blockSize > remaining {
				blockSize >>= 1
			}
			entry := uidLPMKey{PrefixLength: uint32(32 - bits.TrailingZeros64(blockSize))}
			binary.BigEndian.PutUint32(entry.UID[:], uint32(start))
			entries[entry] = struct{}{}
			start += blockSize
		}
	}
	compiled := make([]uidLPMKey, 0, len(entries))
	for entry := range entries {
		compiled = append(compiled, entry)
	}
	sort.Slice(compiled, func(i, j int) bool {
		if compiled[i].PrefixLength != compiled[j].PrefixLength {
			return compiled[i].PrefixLength < compiled[j].PrefixLength
		}
		return binary.BigEndian.Uint32(compiled[i].UID[:]) < binary.BigEndian.Uint32(compiled[j].UID[:])
	})
	return compiled
}

func compileBypassCIDRPolicy(prefixes []netip.Prefix) ([]netip.Prefix, []netip.Prefix, error) {
	var ipv4Builder netipx.IPSetBuilder
	var ipv6Builder netipx.IPSetBuilder
	for _, prefix := range prefixes {
		if !prefix.IsValid() {
			continue
		}
		prefix = prefix.Masked()
		if prefix.Addr().Is4In6() && prefix.Bits() >= 96 {
			prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96).Masked()
		}
		if prefix.Addr().Is4() {
			ipv4Builder.AddPrefix(prefix)
		} else {
			ipv6Builder.AddPrefix(prefix)
		}
	}
	ipv4Set, err := ipv4Builder.IPSet()
	if err != nil {
		return nil, nil, err
	}
	ipv6Set, err := ipv6Builder.IPSet()
	if err != nil {
		return nil, nil, err
	}
	return ipv4Set.Prefixes(), ipv6Set.Prefixes(), nil
}

func bypassCIDRPolicyDelta(
	currentPrefixes []netip.Prefix,
	nextPrefixes []netip.Prefix,
) (additions []netip.Prefix, removals []netip.Prefix) {
	currentSet := make(map[netip.Prefix]struct{}, len(currentPrefixes))
	for _, prefix := range currentPrefixes {
		currentSet[prefix] = struct{}{}
	}
	nextSet := make(map[netip.Prefix]struct{}, len(nextPrefixes))
	for _, prefix := range nextPrefixes {
		nextSet[prefix] = struct{}{}
		if _, loaded := currentSet[prefix]; !loaded {
			additions = append(additions, prefix)
		}
	}
	for _, prefix := range currentPrefixes {
		if _, loaded := nextSet[prefix]; !loaded {
			removals = append(removals, prefix)
		}
	}
	return additions, removals
}
