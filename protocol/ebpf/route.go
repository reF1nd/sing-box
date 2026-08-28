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

type localRoute struct {
	route netlink.Route
}

func (i *Inbound) selectRedirectPrefixes() error {
	loopback, err := netlink.LinkByName("lo")
	if err != nil {
		return E.Cause(err, "find loopback interface")
	}
	i.redirectIPv4Prefix, err = selectRedirectPrefix(
		loopback.Attrs().Index,
		unix.AF_INET,
		redirectIPv4Candidates,
		i.fakeIPPrefixes(),
	)
	if err != nil {
		return E.Cause(err, "select internal IPv4 redirect prefix")
	}
	if i.requiresIPv6Redirect() {
		i.redirectIPv6Prefix, err = selectRedirectPrefix(
			loopback.Attrs().Index,
			unix.AF_INET6,
			redirectIPv6Candidates,
			i.fakeIPPrefixes(),
		)
		if err != nil {
			return E.Cause(err, "select internal IPv6 redirect prefix")
		}
	} else {
		i.redirectIPv6Prefix = netip.Prefix{}
	}
	return nil
}

func selectRedirectPrefix(
	loopbackIndex int,
	family int,
	candidates []netip.Prefix,
	excluded []netip.Prefix,
) (netip.Prefix, error) {
	var conflictErr error
	for _, candidate := range candidates {
		var excludedConflict netip.Prefix
		for _, prefix := range excluded {
			if prefixesOverlap(candidate, prefix) {
				excludedConflict = prefix
				break
			}
		}
		if excludedConflict.IsValid() {
			conflictErr = E.Errors(conflictErr, E.New(
				"eBPF redirect address ", candidate,
				" conflicts with FakeIP range ", excludedConflict,
			))
			continue
		}
		if err := checkRedirectRouteConflict(loopbackIndex, family, candidate); err != nil {
			conflictErr = E.Errors(conflictErr, err)
			continue
		}
		return candidate, nil
	}
	return netip.Prefix{}, conflictErr
}

func (i *Inbound) setupLocalRoutes() error {
	prefixes := make([]netip.Prefix, 0, 2)
	if i.redirectIPv4Prefix.IsValid() {
		prefixes = append(prefixes, i.redirectIPv4Prefix)
	}
	if i.redirectIPv6Prefix.IsValid() &&
		(i.cgroupIPv6Enabled() || i.sharedNetworkIPv6Enabled()) {
		prefixes = append(prefixes, i.redirectIPv6Prefix)
	}
	routes, err := addLocalRoutes(prefixes)
	if err != nil {
		return err
	}
	i.localRoutes = routes
	return nil
}

func (i *Inbound) removeLocalRoutes() error {
	if len(i.localRoutes) == 0 {
		return nil
	}
	routes := i.localRoutes
	var routeErr error
	for index := len(routes) - 1; index >= 0; index-- {
		err := netlink.RouteDel(&routes[index].route)
		if err != nil && !errors.Is(err, unix.ENOENT) && !errors.Is(err, unix.ESRCH) {
			routeErr = E.Errors(routeErr, err)
		}
	}
	if routeErr == nil {
		i.localRoutes = nil
	}
	return routeErr
}

func addLocalRoutes(prefixes []netip.Prefix) ([]*localRoute, error) {
	loopback, err := netlink.LinkByName("lo")
	if err != nil {
		return nil, E.Cause(err, "find loopback interface")
	}
	ownedRoutes := make([]*localRoute, 0, len(prefixes))
	for _, prefix := range prefixes {
		route, owned, routeErr := addLocalRoute(loopback.Attrs().Index, prefix)
		if routeErr != nil {
			for index := len(ownedRoutes) - 1; index >= 0; index-- {
				_ = netlink.RouteDel(&ownedRoutes[index].route)
			}
			return nil, routeErr
		}
		if owned {
			ownedRoutes = append(ownedRoutes, &localRoute{route: route})
		}
	}
	return ownedRoutes, nil
}

func addLocalRoute(loopbackIndex int, prefix netip.Prefix) (netlink.Route, bool, error) {
	family := unix.AF_INET
	if prefix.Addr().Is6() {
		family = unix.AF_INET6
	}
	route := netlink.Route{
		LinkIndex: loopbackIndex,
		Family:    family,
		Dst:       prefixIPNet(prefix),
		Scope:     netlink.Scope(unix.RT_SCOPE_HOST),
		Table:     unix.RT_TABLE_LOCAL,
		Type:      unix.RTN_LOCAL,
	}
	if err := checkRedirectRouteConflict(loopbackIndex, family, prefix); err != nil {
		return netlink.Route{}, false, err
	}
	exists, err := localRouteExists(family, prefix)
	if err != nil {
		return netlink.Route{}, false, err
	}
	if exists {
		return route, false, nil
	}
	if err = netlink.RouteAdd(&route); err != nil {
		if errors.Is(err, unix.EEXIST) {
			exists, listErr := localRouteExists(family, prefix)
			if listErr == nil && exists {
				return route, false, nil
			}
		}
		return netlink.Route{}, false, E.Cause(err, "add local route for ", prefix)
	}
	return route, true, nil
}

func checkRedirectRouteConflict(loopbackIndex int, family int, prefix netip.Prefix) error {
	addresses, err := netlink.AddrList(nil, family)
	if err != nil {
		return E.Cause(err, "list interface addresses for eBPF redirect route")
	}
	for _, address := range addresses {
		if address.LinkIndex == loopbackIndex && prefix.Addr().Is4() {
			continue
		}
		addressPrefix, loaded := prefixFromIPNet(address.IPNet)
		if loaded && prefixesOverlap(prefix, addressPrefix) {
			return E.New("eBPF redirect address ", prefix,
				" conflicts with interface address ", addressPrefix)
		}
	}
	routes, err := netlink.RouteList(nil, family)
	if err != nil {
		return E.Cause(err, "list routes for eBPF redirect address")
	}
	minimumRouteBits := 8
	if prefix.Addr().Is6() {
		minimumRouteBits = 7
	}
	for _, route := range routes {
		if route.LinkIndex == loopbackIndex && prefix.Addr().Is4() {
			continue
		}
		routePrefix, loaded := prefixFromIPNet(route.Dst)
		if !loaded || routePrefix.Bits() < minimumRouteBits {
			continue
		}
		if route.LinkIndex == loopbackIndex && route.Type == unix.RTN_LOCAL && routePrefix == prefix {
			continue
		}
		if prefixesOverlap(prefix, routePrefix) {
			return E.New("eBPF redirect address ", prefix,
				" conflicts with route ", routePrefix)
		}
	}
	return nil
}

func localRouteExists(family int, prefix netip.Prefix) (bool, error) {
	routes, err := netlink.RouteListFiltered(
		family,
		&netlink.Route{Table: unix.RT_TABLE_LOCAL},
		netlink.RT_FILTER_TABLE,
	)
	if err != nil {
		return false, E.Cause(err, "list local routes")
	}
	for _, route := range routes {
		if route.Type == unix.RTN_LOCAL && routePrefixContains(route.Dst, prefix) {
			return true, nil
		}
	}
	return false, nil
}

func prefixIPNet(prefix netip.Prefix) *net.IPNet {
	prefix = prefix.Masked()
	return &net.IPNet{
		IP:   net.IP(prefix.Addr().AsSlice()),
		Mask: net.CIDRMask(prefix.Bits(), prefix.Addr().BitLen()),
	}
}

func routePrefixContains(destination *net.IPNet, prefix netip.Prefix) bool {
	destinationPrefix, loaded := prefixFromIPNet(destination)
	if !loaded {
		return false
	}
	prefix = prefix.Masked()
	if destinationPrefix.Addr().BitLen() != prefix.Addr().BitLen() || destinationPrefix.Bits() > prefix.Bits() {
		return false
	}
	return destinationPrefix.Contains(prefix.Addr())
}

func prefixFromIPNet(network *net.IPNet) (netip.Prefix, bool) {
	if network == nil {
		return netip.Prefix{}, false
	}
	bits, addressBits := network.Mask.Size()
	address, loaded := netip.AddrFromSlice(network.IP)
	if !loaded || bits < 0 {
		return netip.Prefix{}, false
	}
	address = address.Unmap()
	if address.BitLen() != addressBits {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(address, bits).Masked(), true
}

func prefixesOverlap(left netip.Prefix, right netip.Prefix) bool {
	left = left.Masked()
	right = right.Masked()
	if left.Addr().BitLen() != right.Addr().BitLen() {
		return false
	}
	return left.Contains(right.Addr()) || right.Contains(left.Addr())
}
