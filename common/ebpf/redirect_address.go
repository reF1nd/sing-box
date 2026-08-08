package ebpf

import (
	"net/netip"

	E "github.com/sagernet/sing/common/exceptions"
)

var (
	redirectIPv4Range = netip.MustParsePrefix("127.0.0.0/8")
	redirectIPv6Range = netip.MustParsePrefix("fc00::/7")
)

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
