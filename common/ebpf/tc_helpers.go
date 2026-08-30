//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net/netip"

	E "github.com/sagernet/sing/common/exceptions"
)

func normalizeAddressPrefix(name string, prefix netip.Prefix, ipv4 bool) (netip.Prefix, error) {
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
