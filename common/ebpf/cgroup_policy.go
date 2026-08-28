//go:build with_ebpf && (linux || android)

package ebpf

import (
	"encoding/binary"
	"math/bits"
	"net/netip"
	"sort"

	E "github.com/sagernet/sing/common/exceptions"

	"go4.org/netipx"
)

const (
	maxUIDPolicyEntries         = 4096
	maxBypassCIDRPolicyEntries  = 65536
	maxHostAddressPolicyEntries = 4096
)

type DNSMode uint16

const (
	DNSModeHijack DNSMode = iota
	DNSModeRespectPolicy
	DNSModeOff
)

type CgroupPolicy struct {
	EnableBypassCIDR     bool
	DNSMode              DNSMode
	BypassPrivateAddress bool
	IncludeUIDConfigured bool
	IncludeUID           []UIDRange
	ExcludeUID           []UIDRange
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

type BypassCIDRPolicy struct {
	ipv4 []netip.Prefix
	ipv6 []netip.Prefix
}

func (p BypassCIDRPolicy) Count() (int, int) {
	return len(p.ipv4), len(p.ipv6)
}

func CompileBypassCIDRPolicy(prefixes []netip.Prefix) (BypassCIDRPolicy, error) {
	ipv4, ipv6, err := compileBypassCIDRPolicy(prefixes)
	return BypassCIDRPolicy{ipv4: ipv4, ipv6: ipv6}, err
}

func compileUIDPolicy(policy CgroupPolicy) ([]uidLPMKey, bool, error) {
	for name, uidRanges := range map[string][]UIDRange{
		"include_uid": policy.IncludeUID,
		"exclude_uid": policy.ExcludeUID,
	} {
		for _, uidRange := range uidRanges {
			if uidRange.Start > uidRange.End {
				return nil, false, E.New("invalid ", name, " range: ", uidRange.Start, ":", uidRange.End)
			}
		}
	}
	defaultBypass := policy.IncludeUIDConfigured || len(policy.IncludeUID) > 0
	uidRanges := policy.ExcludeUID
	if defaultBypass {
		uidRanges = subtractUIDRanges(policy.IncludeUID, policy.ExcludeUID)
	}
	entries := compileUIDRanges(uidRanges)
	if len(entries) > maxUIDPolicyEntries {
		return nil, false, E.New("UID policy compiles to too many eBPF map entries: ", len(entries), " > ", maxUIDPolicyEntries)
	}
	return entries, defaultBypass, nil
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

func normalizeUIDRanges(uidRanges []UIDRange) []UIDRange {
	if len(uidRanges) == 0 {
		return nil
	}
	normalized := append([]UIDRange(nil), uidRanges...)
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

func subtractUIDRanges(includeRanges []UIDRange, excludeRanges []UIDRange) []UIDRange {
	includeRanges = normalizeUIDRanges(includeRanges)
	excludeRanges = normalizeUIDRanges(excludeRanges)
	result := make([]UIDRange, 0, len(includeRanges))
	excludeIndex := 0
	for _, includeRange := range includeRanges {
		start := uint64(includeRange.Start)
		end := uint64(includeRange.End)
		for excludeIndex < len(excludeRanges) && uint64(excludeRanges[excludeIndex].End) < start {
			excludeIndex++
		}
		for index := excludeIndex; index < len(excludeRanges); index++ {
			excludeRange := excludeRanges[index]
			if uint64(excludeRange.Start) > end {
				break
			}
			if uint64(excludeRange.Start) > start {
				result = append(result, UIDRange{Start: uint32(start), End: excludeRange.Start - 1})
			}
			if uint64(excludeRange.End) >= end {
				start = end + 1
				break
			}
			start = uint64(excludeRange.End) + 1
		}
		if start <= end {
			result = append(result, UIDRange{Start: uint32(start), End: uint32(end)})
		}
	}
	return result
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
