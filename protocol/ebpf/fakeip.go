//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net/netip"

	E "github.com/sagernet/sing/common/exceptions"
)

var (
	fakeIPSafetyIPv4Prefixes = []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/8"),
		netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("224.0.0.0/4"),
	}
	fakeIPSafetyIPv6Prefixes = []netip.Prefix{
		netip.MustParsePrefix("::/128"),
		netip.MustParsePrefix("::1/128"),
		netip.MustParsePrefix("::ff00:0:0/104"),
		netip.MustParsePrefix("ff00::/8"),
	}
)

func (i *Inbound) normalizeFakeIPPrefixes() error {
	for name, entry := range map[string]struct {
		prefix *netip.Prefix
		ipv4   bool
		safety []netip.Prefix
	}{
		"IPv4": {&i.fakeIPIPv4Prefix, true, fakeIPSafetyIPv4Prefixes},
		"IPv6": {&i.fakeIPIPv6Prefix, false, fakeIPSafetyIPv6Prefixes},
	} {
		prefix := *entry.prefix
		if !prefix.IsValid() {
			continue
		}
		prefix = prefix.Masked()
		if prefix.Addr().Is4() != entry.ipv4 || prefix.Addr().Is4In6() {
			return E.New("invalid ", name, " FakeIP range for eBPF inbound: ", prefix)
		}
		for _, safetyPrefix := range entry.safety {
			if prefixesOverlap(prefix, safetyPrefix) {
				return E.New(
					name, " FakeIP range ", prefix,
					" overlaps mandatory eBPF safety bypass ", safetyPrefix,
				)
			}
		}
		*entry.prefix = prefix
	}
	return nil
}

func (i *Inbound) fakeIPPrefixes() []netip.Prefix {
	prefixes := make([]netip.Prefix, 0, 2)
	if i.fakeIPIPv4Prefix.IsValid() {
		prefixes = append(prefixes, i.fakeIPIPv4Prefix)
	}
	if i.fakeIPIPv6Prefix.IsValid() {
		prefixes = append(prefixes, i.fakeIPIPv6Prefix)
	}
	return prefixes
}
