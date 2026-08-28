//go:build with_ebpf && (linux || android)

package ebpf

import "net/netip"

func (i *Inbound) cgroupIPv6Enabled() bool {
	return i.cgroupEnabled && i.localIPv6 && i.redirectIPv6Prefix.IsValid()
}

func (i *Inbound) sharedNetworkIPv6Enabled() bool {
	return i.sharedNetworkEnabled && i.sharedIPv6 && i.redirectIPv6Prefix.IsValid()
}

func (i *Inbound) requiresIPv6Redirect() bool {
	return i.cgroupEnabled && i.localIPv6 || i.sharedNetworkEnabled && i.sharedIPv6
}

func (i *Inbound) sharedRedirectIPv6Prefix() netip.Prefix {
	if !i.sharedNetworkIPv6Enabled() {
		return netip.Prefix{}
	}
	return i.redirectIPv6Prefix
}
