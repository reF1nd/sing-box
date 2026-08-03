//go:build with_ebpf && (linux || android) && cgo

package ebpf

import (
	"net/netip"
	"slices"

	E "github.com/sagernet/sing/common/exceptions"
)

func (b *SharedNetworkBackend) UpdateBypassCIDR(prefixes []netip.Prefix) (bool, error) {
	ipv4, ipv6, err := compileBypassCIDRPolicy(prefixes)
	if err != nil {
		return false, E.Cause(err, "compile shared-network bypass CIDR policy")
	}
	if len(ipv4) > maxBypassCIDRPolicyEntries || len(ipv6) > maxBypassCIDRPolicyEntries {
		return false, E.New("shared-network bypass CIDR policy exceeds eBPF map capacity")
	}
	if b == nil {
		return false, errBackendClosed
	}
	b.access.Lock()
	defer b.access.Unlock()
	if b.runtime == nil || b.bypassIPv4MapFD < 0 || b.bypassIPv6MapFD < 0 {
		return false, errBackendClosed
	}
	changed, err := replaceDualStackCIDRPolicy(
		b.bypassIPv4MapFD,
		b.bypassIPv6MapFD,
		dualStackCIDRPrefixes{b.bypassIPv4CIDR, b.bypassIPv6CIDR},
		dualStackCIDRPrefixes{ipv4, ipv6},
		"shared-network ",
		"bypass CIDR",
	)
	if err != nil {
		return false, err
	}
	oldIPv4 := b.bypassIPv4CIDR
	oldIPv6 := b.bypassIPv6CIDR
	oldFlags := b.control.Flags
	b.bypassIPv4CIDR = slices.Clone(ipv4)
	b.bypassIPv6CIDR = slices.Clone(ipv6)
	if err = b.updatePolicyFlagsLocked(); err != nil {
		b.bypassIPv4CIDR = oldIPv4
		b.bypassIPv6CIDR = oldIPv6
		b.control.Flags = oldFlags
		return false, err
	}
	return changed, nil
}

func (b *SharedNetworkBackend) BypassCIDRCount() (int, int) {
	if b == nil {
		return 0, 0
	}
	b.access.RLock()
	defer b.access.RUnlock()
	return len(b.bypassIPv4CIDR), len(b.bypassIPv6CIDR)
}

func (b *SharedNetworkBackend) UpdateHostAddresses(addresses []netip.Addr) error {
	if b == nil {
		return errBackendClosed
	}
	ipv4, ipv6 := compileSharedHostPrefixes(addresses)
	if len(ipv4) > 256 || len(ipv6) > 256 {
		return E.New("shared-network host address policy exceeds eBPF map capacity")
	}
	b.access.Lock()
	defer b.access.Unlock()
	if b.runtime == nil {
		return errBackendClosed
	}
	_, err := replaceDualStackCIDRPolicy(
		int(b.runtime.host_ipv4_map_fd),
		int(b.runtime.host_ipv6_map_fd),
		dualStackCIDRPrefixes{b.hostIPv4, b.hostIPv6},
		dualStackCIDRPrefixes{ipv4, ipv6},
		"shared-network ",
		"host",
	)
	if err != nil {
		return err
	}
	oldIPv4 := b.hostIPv4
	oldIPv6 := b.hostIPv6
	oldFlags := b.control.Flags
	b.hostIPv4 = ipv4
	b.hostIPv6 = ipv6
	if err = b.updatePolicyFlagsLocked(); err != nil {
		b.hostIPv4 = oldIPv4
		b.hostIPv6 = oldIPv6
		b.control.Flags = oldFlags
		return err
	}
	return nil
}

// SetBypassCIDRState updates only policy presence flags when the maps are
// owned by a cgroup backend and shared-network reuses those descriptors.
func (b *SharedNetworkBackend) SetBypassCIDRState(prefixes []netip.Prefix) error {
	if b == nil {
		return errBackendClosed
	}
	ipv4, ipv6, err := compileBypassCIDRPolicy(prefixes)
	if err != nil {
		return E.Cause(err, "compile shared-network bypass CIDR state")
	}
	b.access.Lock()
	defer b.access.Unlock()
	if b.runtime == nil {
		return errBackendClosed
	}
	oldFlags := b.control.Flags
	b.control.Flags &^= sharedNetworkFlagBypassIPv4 | sharedNetworkFlagBypassIPv6
	if len(ipv4) != 0 {
		b.control.Flags |= sharedNetworkFlagBypassIPv4
	}
	if len(ipv6) != 0 {
		b.control.Flags |= sharedNetworkFlagBypassIPv6
	}
	if err = b.updateControl(); err != nil {
		b.control.Flags = oldFlags
	}
	return err
}

func (b *SharedNetworkBackend) updatePolicyFlagsLocked() error {
	b.control.Flags &^= sharedNetworkPolicyFlags
	if len(b.hostIPv4) != 0 {
		b.control.Flags |= sharedNetworkFlagHostIPv4
	}
	if len(b.hostIPv6) != 0 {
		b.control.Flags |= sharedNetworkFlagHostIPv6
	}
	if len(b.bypassIPv4CIDR) != 0 {
		b.control.Flags |= sharedNetworkFlagBypassIPv4
	}
	if len(b.bypassIPv6CIDR) != 0 {
		b.control.Flags |= sharedNetworkFlagBypassIPv6
	}
	return b.updateControl()
}
