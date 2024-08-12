package rule

import (
	"bytes"
	"encoding/binary"
	"math/bits"
	"net/netip"

	"github.com/sagernet/sing-box/common/ipset"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/domain"

	"go4.org/netipx"
)

// countDefaultHeadlessRule returns how many entries a rule expands to. Values that match
// on their own are counted one by one, while conditions that must all match are one rule.
func countDefaultHeadlessRule(rule *DefaultHeadlessRule, options option.DefaultHeadlessRule) uint64 {
	var count uint64
	switch len(rule.allItems) {
	case len(rule.destinationAddressItems) + len(rule.destinationIPCIDRItems):
		count = countDomainEntries(options) +
			countAdGuardDomainEntries(options) +
			uint64(len(options.DomainKeyword)+len(options.DomainRegex)) +
			countIPEntries(len(options.IPCIDR), options.IPSet)
	case len(rule.sourceAddressItems):
		count = countIPEntries(len(options.SourceIPCIDR), options.SourceIPSet)
	case len(rule.sourcePortItems):
		count = uint64(len(options.SourcePort) + len(options.SourcePortRange))
	case len(rule.destinationPortItems):
		count = uint64(len(options.Port) + len(options.PortRange))
	case 1:
		// network_interface_address and default_interface_address are left out on purpose:
		// all of their values have to match, so they stay one rule.
		count = uint64(len(options.QueryType) + len(options.Network) +
			len(options.ProcessName) + len(options.ProcessPath) + len(options.ProcessPathRegex) +
			len(options.PackageName) + len(options.PackageNameRegex) +
			len(options.NetworkType) + len(options.WIFISSID) + len(options.WIFIBSSID))
	}
	return max(count, 1)
}

func countDomainEntries(options option.DefaultHeadlessRule) uint64 {
	if len(options.Domain) > 0 || len(options.DomainSuffix) > 0 {
		return uint64(len(options.Domain) + len(options.DomainSuffix))
	}
	if options.DomainMatcher != nil {
		return countDomainMatcher(options.DomainMatcher.Mmap())
	}
	return 0
}

func countAdGuardDomainEntries(options option.DefaultHeadlessRule) uint64 {
	if len(options.AdGuardDomain) > 0 {
		return uint64(len(options.AdGuardDomain))
	}
	if options.AdGuardDomainMatcher != nil {
		return uint64(countSetBits(options.AdGuardDomainMatcher.Mmap().Leaves))
	}
	return 0
}

// countIPEntries falls back to the IP set for binary rule-sets. These only keep merged ranges,
// so the entries are counted as the CIDR prefixes needed to cover each range.
func countIPEntries(prefixCount int, ipSet *ipset.Set) uint64 {
	if prefixCount > 0 {
		return uint64(prefixCount)
	}
	if ipSet == nil {
		return 0
	}
	var count int
	var prefixes []netip.Prefix
	for _, ipRange := range ipSet.Ranges4() {
		var from, to [4]byte
		binary.BigEndian.PutUint32(from[:], ipRange.From)
		binary.BigEndian.PutUint32(to[:], ipRange.To)
		prefixes = netipx.IPRangeFrom(netip.AddrFrom4(from), netip.AddrFrom4(to)).AppendPrefixes(prefixes[:0])
		count += len(prefixes)
	}
	for _, ipRange := range ipSet.Ranges6() {
		prefixes = netipx.IPRangeFrom(netip.AddrFrom16(ipRange.From), netip.AddrFrom16(ipRange.To)).AppendPrefixes(prefixes[:0])
		count += len(prefixes)
	}
	return uint64(count)
}

// countDomainMatcher counts the entries of a compiled domain matcher without dumping its keys,
// which would allocate every domain while the rule-set is loading.
//
// Each key owns one leaf bit, but legacy (version 1) rule-sets store an undotted suffix as two
// keys, "example.com" and "\r.example.com", so these pairs are found and counted once. Reversed,
// the second key continues the first one with the labels '.' and '\r'.
func countDomainMatcher(data domain.Mmap) uint64 {
	count := countSetBits(data.Leaves)
	if bytes.IndexByte(data.Labels, '\r') < 0 {
		return uint64(count)
	}
	// Nodes are numbered breadth-first: edge i leads to node i+1, so every node is marked
	// here before it is visited.
	nodesAfterDot := make([]uint64, len(data.Leaves))
	var node, edge int
	for index := 0; edge < len(data.Labels); index++ {
		if isBitSet(data.LabelBitmap, index) {
			node++
			continue
		}
		label := data.Labels[edge]
		edge++
		switch label {
		case '.':
			if isBitSet(data.Leaves, node) {
				nodesAfterDot[edge>>6] |= 1 << uint(edge&63)
			}
		case '\r':
			if isBitSet(nodesAfterDot, node) {
				count--
			}
		}
	}
	return uint64(max(count, 0))
}

func countSetBits(bitmap []uint64) int {
	var count int
	for _, word := range bitmap {
		count += bits.OnesCount64(word)
	}
	return count
}

func isBitSet(bitmap []uint64, index int) bool {
	return bitmap[index>>6]&(1<<uint(index&63)) != 0
}
