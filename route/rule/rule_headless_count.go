package rule

import (
	"bytes"
	"encoding/binary"
	"math/bits"
	"net/netip"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/domain"
	"github.com/sagernet/sing/common/varbin"

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
		return countDomainMatcher(options.DomainMatcher)
	}
	return 0
}

func countAdGuardDomainEntries(options option.DefaultHeadlessRule) uint64 {
	if len(options.AdGuardDomain) > 0 {
		return uint64(len(options.AdGuardDomain))
	}
	if options.AdGuardDomainMatcher != nil {
		leaves, _, _, loaded := matcherTrie(options.AdGuardDomainMatcher)
		if !loaded {
			return 0
		}
		return uint64(countSetBits(leaves))
	}
	return 0
}

// countIPEntries falls back to the IP set for binary rule-sets. These only keep merged ranges,
// so the entries are counted as the CIDR prefixes needed to cover each range.
func countIPEntries(prefixCount int, ipSet *netipx.IPSet) uint64 {
	if prefixCount > 0 {
		return uint64(prefixCount)
	}
	if ipSet == nil {
		return 0
	}
	var count int
	var prefixes []netip.Prefix
	for _, ipRange := range ipSet.Ranges() {
		prefixes = ipRange.AppendPrefixes(prefixes[:0])
		count += len(prefixes)
	}
	return uint64(count)
}

type compiledMatcher interface {
	Write(writer varbin.Writer) error
}

// matcherTrieWriter keeps what a compiled matcher serializes, the binary rule-set format, which
// is the only access matchers provide to their trie. Each section of the trie arrives in one
// Write call and is kept without copying: it is only read while the trie is being counted.
type matcherTrieWriter struct {
	sections [][]byte
}

func (w *matcherTrieWriter) Write(section []byte) (int, error) {
	w.sections = append(w.sections, section)
	return len(section), nil
}

func (w *matcherTrieWriter) WriteByte(byte) error {
	return nil
}

func matcherTrie(matcher compiledMatcher) (leaves, labelBitmap, labels []byte, loaded bool) {
	var writer matcherTrieWriter
	if matcher.Write(&writer) != nil || len(writer.sections) != 3 {
		return nil, nil, nil, false
	}
	return writer.sections[0], writer.sections[1], writer.sections[2], true
}

// countDomainMatcher counts the entries of a compiled domain matcher without dumping its keys,
// which would allocate every domain while the rule-set is loading.
//
// Each key owns one leaf bit, but legacy (version 1) rule-sets store an undotted suffix as two
// keys, "example.com" and "\r.example.com", so these pairs are found and counted once. Reversed,
// the second key continues the first one with the labels '.' and '\r'.
func countDomainMatcher(matcher *domain.Matcher) uint64 {
	leaves, labelBitmap, labels, loaded := matcherTrie(matcher)
	if !loaded {
		return 0
	}
	count := countSetBits(leaves)
	if bytes.IndexByte(labels, '\r') < 0 {
		return uint64(count)
	}
	// Nodes are numbered breadth-first: edge i leads to node i+1, so every node is marked
	// here before it is visited.
	nodesAfterDot := make([]byte, len(leaves))
	var node, edge int
	for index := 0; edge < len(labels); index++ {
		if isBitSet(labelBitmap, index) {
			node++
			continue
		}
		label := labels[edge]
		edge++
		switch label {
		case '.':
			if isBitSet(leaves, node) {
				nodesAfterDot[bitOffset(edge)] |= bitMask(edge)
			}
		case '\r':
			if isBitSet(nodesAfterDot, node) {
				count--
			}
		}
	}
	return uint64(max(count, 0))
}

// Bitmaps are stored as big-endian 64-bit words.
func countSetBits(bitmap []byte) int {
	var count int
	for offset := 0; offset+8 <= len(bitmap); offset += 8 {
		count += bits.OnesCount64(binary.BigEndian.Uint64(bitmap[offset:]))
	}
	return count
}

func isBitSet(bitmap []byte, index int) bool {
	return bitmap[bitOffset(index)]&bitMask(index) != 0
}

func bitOffset(index int) int {
	return index>>6<<3 + 7 - index&63>>3
}

func bitMask(index int) byte {
	return 1 << uint(index&7)
}
