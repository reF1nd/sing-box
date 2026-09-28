//go:build with_ebpf && (linux || android)

package ebpf

func (i *Inbound) cgroupIPv6Enabled() bool {
	return i.localCgroupEnabled() && i.localIPv6 && i.redirectIPv6Prefix.IsValid()
}

func (i *Inbound) requiresIPv6Redirect() bool {
	return i.localCgroupEnabled() && i.localIPv6 || i.sharedRewriteEnabled() && i.sharedIPv6
}

func (i *Inbound) sharedRewriteIPv6Enabled() bool {
	return i.sharedRewriteEnabled() && i.sharedIPv6 && i.redirectIPv6Prefix.IsValid()
}
