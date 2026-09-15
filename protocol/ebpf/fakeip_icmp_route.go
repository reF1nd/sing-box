//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"net"
	"net/netip"

	"github.com/sagernet/netlink"

	E "github.com/sagernet/sing/common/exceptions"
	"golang.org/x/sys/unix"
)

// warnIfLocalFakeIPICMPIPv6Unroutable is a diagnostic only: fakeip_icmp=reply
// for local IPv6 depends on ordinary routing actually sending an IPv6 packet
// out the local TC interface for local_reply's egress classifier to see it
// at all (see docs/configuration/inbound/ebpf.md's fakeip_icmp section).
// Without a route to the FakeIP prefix through that interface — a default
// route satisfies this, the same way it does for IPv4 — a local ping to the
// FakeIP range fails at the kernel's own route lookup before ever reaching this
// object, and would otherwise look like an unexplained timeout with nothing
// in the log to point at the real cause. This never blocks startup or
// reconciliation: unlike local.data_plane=cgroup, which can never support
// fakeip_icmp regardless of the network, missing IPv6 connectivity here is
// ordinary transient network state that can resolve itself.
func (i *Inbound) warnIfLocalFakeIPICMPIPv6Unroutable(localInterface string) {
	if localInterface == "" || !i.fakeIPICMPReply || !i.localIPv6 || !i.fakeIPIPv6Prefix.IsValid() {
		return
	}
	link, err := netlink.LinkByName(localInterface)
	if err != nil {
		// The topology warning already covers a local interface that cannot
		// be resolved; this check has nothing further to add.
		return
	}
	routable, err := interfaceRoutesIPv6Prefix(link, i.fakeIPIPv6Prefix)
	if err != nil {
		i.interfaceWarnings.fakeIPICMPRoute.warn(
			i.logger, "inspect local IPv6 route for fakeip_icmp on interface ", localInterface, ": ", err,
		)
		return
	}
	if !routable {
		i.interfaceWarnings.fakeIPICMPRoute.warn(
			i.logger,
			"fakeip_icmp=reply has no IPv6 route out local interface ", localInterface,
			"; a local IPv6 ping to the FakeIP range will not be answered until this host has real IPv6 connectivity",
		)
	}
}

// interfaceRoutesIPv6Prefix asks the kernel to resolve an address in prefix
// and confirms that the selected route leaves through link. Merely having an
// unrelated global connected route on the interface is insufficient: without
// a matching or default route the packet never reaches the TC classifier.
func interfaceRoutesIPv6Prefix(link netlink.Link, prefix netip.Prefix) (bool, error) {
	destination := prefix.Masked().Addr()
	routes, err := netlink.RouteGet(net.IP(destination.AsSlice()))
	if errors.Is(err, unix.ENETUNREACH) || errors.Is(err, unix.EHOSTUNREACH) {
		return false, nil
	}
	if err != nil {
		return false, E.Cause(err, "resolve IPv6 route to ", destination)
	}
	for _, route := range routes {
		if route.LinkIndex == link.Attrs().Index {
			return true, nil
		}
		for _, nextHop := range route.MultiPath {
			if nextHop.LinkIndex == link.Attrs().Index {
				return true, nil
			}
		}
	}
	return false, nil
}
