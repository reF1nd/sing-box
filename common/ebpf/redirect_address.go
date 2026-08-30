//go:build with_ebpf && (linux || android)

package ebpf

import (
	"encoding/binary"
	"math"
	"net/netip"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
)

const userspaceReplyTokenAttempts = 32

func userspaceReplyToken(prefix netip.Prefix, sequence uint64) (netip.Addr, bool) {
	prefix = prefix.Masked()
	if !prefix.IsValid() || sequence == 0 {
		return netip.Addr{}, false
	}
	if prefix.Addr().Is4() {
		hostBits := 32 - prefix.Bits()
		if hostBits <= 0 || hostBits >= 32 {
			return netip.Addr{}, false
		}
		hostMask := uint32(1<<hostBits) - 1
		host := uint32(sequence) & hostMask
		if host == 0 || host == hostMask {
			return netip.Addr{}, false
		}
		address := prefix.Addr().As4()
		binary.BigEndian.PutUint32(address[:], binary.BigEndian.Uint32(address[:])|host)
		return netip.AddrFrom4(address), true
	}
	if !prefix.Addr().Is6() || prefix.Bits() != 64 {
		return netip.Addr{}, false
	}
	address := prefix.Addr().As16()
	binary.BigEndian.PutUint64(address[8:], sequence)
	return netip.AddrFrom16(address), true
}

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
		if prefix.Bits() < 8 || prefix.Bits() > 10 || !redirectIPv4Range.Contains(prefix.Addr()) {
			return E.New("IPv4 eBPF redirect address must use a /8-/10 prefix in ", redirectIPv4Range)
		}
		return nil
	}
	if prefix.Addr().Is6() && !prefix.Addr().Is4In6() && prefix.Bits() == 64 && redirectIPv6Range.Contains(prefix.Addr()) {
		return nil
	}
	return E.New("invalid IPv6 eBPF redirect address: ", prefix)
}

func cgroupUDPTimeoutSeconds(timeout time.Duration) (uint32, error) {
	if timeout <= 0 {
		return 0, E.New("invalid local cgroup UDP timeout: ", timeout)
	}
	seconds := uint64(timeout / time.Second)
	if timeout%time.Second != 0 {
		seconds++
	}
	if seconds > math.MaxUint32 {
		return 0, E.New("local cgroup UDP timeout is too large: ", timeout)
	}
	return uint32(seconds), nil
}
