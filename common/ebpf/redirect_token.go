//go:build with_ebpf && (linux || android)

package ebpf

import (
	"encoding/binary"
	"net/netip"
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
		candidate := binary.BigEndian.Uint32(address[:]) | host
		binary.BigEndian.PutUint32(address[:], candidate)
		return netip.AddrFrom4(address), true
	}
	if !prefix.Addr().Is6() || prefix.Bits() != 64 {
		return netip.Addr{}, false
	}
	address := prefix.Addr().As16()
	binary.BigEndian.PutUint64(address[8:], sequence)
	return netip.AddrFrom16(address), true
}
