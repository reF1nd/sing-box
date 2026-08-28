package ebpf

import (
	"net/netip"

	E "github.com/sagernet/sing/common/exceptions"
)

var (
	redirectIPv4Range = netip.MustParsePrefix("127.0.0.0/8")
	redirectIPv6Range = netip.MustParsePrefix("fc00::/7")
)

func normalizeAddressPrefix(name string, prefix netip.Prefix, ipv4 bool) (netip.Prefix, error) { //nolint:unused // Used by eBPF-tagged backends.
	if !prefix.IsValid() {
		return netip.Prefix{}, nil
	}
	prefix = prefix.Masked()
	if prefix.Addr().Is4() != ipv4 || prefix.Addr().Is4In6() {
		return netip.Prefix{}, E.New("invalid ", name, ": ", prefix)
	}
	return prefix, nil
}

func prefixMask4(bits int) (mask [4]byte) {
	fillPrefixMask(mask[:], bits)
	return
}

func prefixMask16(bits int) (mask [16]byte) {
	fillPrefixMask(mask[:], bits)
	return
}

func fillPrefixMask(mask []byte, bits int) {
	for index := range mask {
		if bits >= 8 {
			mask[index] = 0xff
			bits -= 8
		} else if bits > 0 {
			mask[index] = 0xff << (8 - bits)
			bits = 0
		}
	}
}

func ValidateRedirectPrefix(prefix netip.Prefix) error {
	if !prefix.IsValid() {
		return E.New("invalid eBPF redirect address")
	}
	prefix = prefix.Masked()
	if prefix.Addr().Is4() {
		if prefix.Bits() < 8 || prefix.Bits() > 10 {
			return E.New("IPv4 eBPF redirect address must use a prefix between /8 and /10")
		}
		if !redirectIPv4Range.Contains(prefix.Addr()) {
			return E.New("IPv4 eBPF redirect address must be within ", redirectIPv4Range)
		}
		return nil
	}
	if prefix.Addr().Is6() && !prefix.Addr().Is4In6() {
		if prefix.Bits() != 64 {
			return E.New("IPv6 eBPF redirect address must use a /64 prefix")
		}
		if !redirectIPv6Range.Contains(prefix.Addr()) {
			return E.New("IPv6 eBPF redirect address must be within ", redirectIPv6Range)
		}
		return nil
	}
	return E.New("invalid eBPF redirect address family: ", prefix)
}
