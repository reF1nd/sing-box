//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"slices"

	"github.com/sagernet/netlink"
	commonEBPF "github.com/sagernet/sing-box/common/ebpf"
	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/sys/unix"
)

const (
	// Preferred values keep diagnostics stable; allocation below always checks
	// the live policy database before using them.
	tcPolicyRoutingTable    = 2027
	tcPolicyRoutingPriority = 8999
	tcPolicyTableMin        = 2000
	tcPolicyTableMax        = 32766
	tcPolicyPriorityMin     = 8000
	tcPolicyPriorityMax     = 32000
)

type tcPolicyRouting struct {
	lock     io.Closer
	mark     uint32
	table    int
	priority int
	families []int
	routes   []netlink.Route
	rules    []*netlink.Rule
}

type tcStalePolicyRouting struct {
	routes []netlink.Route
	rule   *netlink.Rule
}

func startTCPolicyRouting(enableIPv6 bool) (*tcPolicyRouting, error) {
	lock, err := net.ListenUnixgram("unixgram", &net.UnixAddr{
		Name: "@sing-box-ebpf-tc-routing",
		Net:  "unixgram",
	})
	if err != nil {
		if errors.Is(err, unix.EADDRINUSE) {
			return nil, E.New("TC eBPF policy routing is already managed by another inbound")
		}
		return nil, E.Cause(err, "lock TC eBPF policy routing")
	}
	routing := &tcPolicyRouting{lock: lock}
	cleanup := func(startErr error) (*tcPolicyRouting, error) {
		return nil, E.Errors(startErr, routing.Close())
	}
	loopback, err := netlink.LinkByName("lo")
	if err != nil {
		return cleanup(E.Cause(err, "find loopback interface for TC eBPF policy routing"))
	}
	families := []int{unix.AF_INET}
	if enableIPv6 {
		families = append(families, unix.AF_INET6)
	}
	routing.families = families
	identifiers, err := allocateTCPolicyIdentifiers(loopback.Attrs().Index, families)
	if err != nil {
		return cleanup(err)
	}
	routing.mark = identifiers.mark
	routing.table = identifiers.table
	routing.priority = identifiers.priority
	staleRouting := make([]tcStalePolicyRouting, 0, len(families))
	for _, family := range families {
		stale, inspectErr := inspectTCPolicyRoutingFamily(loopback.Attrs().Index, family, routing)
		if inspectErr != nil {
			return cleanup(inspectErr)
		}
		staleRouting = append(staleRouting, stale)
	}
	for _, stale := range staleRouting {
		if err = removeStaleTCPolicyRouting(stale); err != nil {
			return cleanup(err)
		}
	}
	for _, family := range families {
		for _, route := range tcPolicyRoutesForTable(loopback.Attrs().Index, family, routing.table) {
			if err = netlink.RouteAdd(&route); err != nil {
				return cleanup(E.Cause(err, "add TC eBPF local route ", route.Dst))
			}
			routing.routes = append(routing.routes, route)
		}
	}
	for _, family := range families {
		rule := tcPolicyRuleFor(family, routing.mark, routing.table, routing.priority)
		if err = netlink.RuleAdd(rule); err != nil {
			return cleanup(E.Cause(err, "add TC eBPF policy rule"))
		}
		routing.rules = append(routing.rules, rule)
	}
	return routing, nil
}

func (r *tcPolicyRouting) ensure() (bool, error) {
	if r == nil {
		return false, E.New("TC eBPF policy routing is unavailable")
	}
	changed := false
	for _, family := range r.families {
		expectedRoutes := make([]netlink.Route, 0, len(r.routes))
		for _, route := range r.routes {
			if route.Family == family {
				expectedRoutes = append(expectedRoutes, route)
			}
		}
		routes, err := netlink.RouteListFiltered(
			family,
			&netlink.Route{Table: r.table},
			netlink.RT_FILTER_TABLE,
		)
		if err != nil {
			return changed, E.Cause(err, "inspect TC eBPF routing table")
		}
		for _, route := range routes {
			if !matchesTCPolicyRoute(route, expectedRoutes) {
				return changed, E.New("TC eBPF routing table ", r.table, " is already in use")
			}
		}
		for index := range expectedRoutes {
			expected := &expectedRoutes[index]
			if slices.ContainsFunc(routes, func(route netlink.Route) bool {
				return matchesTCPolicyRoute(route, []netlink.Route{*expected})
			}) {
				continue
			}
			if err = netlink.RouteAdd(expected); err != nil {
				return changed, E.Cause(err, "restore TC eBPF local route ", expected.Dst)
			}
			changed = true
		}

		expectedRule := tcPolicyRuleFor(family, r.mark, r.table, r.priority)
		rules, err := netlink.RuleList(family)
		if err != nil {
			return changed, E.Cause(err, "inspect TC eBPF policy rules")
		}
		rulePresent := false
		for _, rule := range rules {
			if matchesTCPolicyRule(rule, *expectedRule) {
				rulePresent = true
				continue
			}
			if rule.Table == r.table {
				return changed, E.New("TC eBPF routing table ", r.table, " is referenced by another policy rule")
			}
		}
		if !rulePresent {
			if err = netlink.RuleAdd(expectedRule); err != nil {
				return changed, E.Cause(err, "restore TC eBPF policy rule")
			}
			changed = true
		}
	}
	return changed, nil
}

func inspectTCPolicyRoutingFamily(loopbackIndex int, family int, routing *tcPolicyRouting) (tcStalePolicyRouting, error) {
	expectedRoutes := tcPolicyRoutesForTable(loopbackIndex, family, routing.table)
	routes, err := netlink.RouteListFiltered(
		family,
		&netlink.Route{Table: routing.table},
		netlink.RT_FILTER_TABLE,
	)
	if err != nil {
		return tcStalePolicyRouting{}, E.Cause(err, "inspect TC eBPF routing table")
	}
	staleRoutes := make([]netlink.Route, 0, len(routes))
	for index := range routes {
		if !matchesTCPolicyRoute(routes[index], expectedRoutes) {
			return tcStalePolicyRouting{}, E.New("TC eBPF routing table ", routing.table, " is already in use")
		}
		staleRoutes = append(staleRoutes, routes[index])
	}
	expectedRule := tcPolicyRuleFor(family, routing.mark, routing.table, routing.priority)
	rules, err := netlink.RuleList(family)
	if err != nil {
		return tcStalePolicyRouting{}, E.Cause(err, "inspect TC eBPF policy rules")
	}
	staleRule := false
	for index := range rules {
		rule := &rules[index]
		if matchesTCPolicyRule(*rule, *expectedRule) {
			staleRule = true
			continue
		}
		if rule.Table == routing.table {
			return tcStalePolicyRouting{}, E.New("TC eBPF routing table ", routing.table, " is referenced by another policy rule")
		}
	}
	stale := tcStalePolicyRouting{routes: staleRoutes}
	if staleRule {
		stale.rule = expectedRule
	}
	return stale, nil
}

func removeStaleTCPolicyRouting(stale tcStalePolicyRouting) error {
	if stale.rule != nil {
		if err := netlink.RuleDel(stale.rule); !tcPolicyDeleteIgnored(err) {
			return E.Cause(err, "remove stale TC eBPF policy rule")
		}
	}
	for index := range slices.Backward(stale.routes) {
		if err := netlink.RouteDel(&stale.routes[index]); !tcPolicyDeleteIgnored(err) {
			return E.Cause(err, "remove stale TC eBPF local route")
		}
	}
	return nil
}

func tcPolicyRoutes(loopbackIndex int, family int) []netlink.Route {
	return tcPolicyRoutesForTable(loopbackIndex, family, tcPolicyRoutingTable)
}

func tcPolicyRoutesForTable(loopbackIndex int, family int, table int) []netlink.Route {
	prefixes := []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/1"),
		netip.MustParsePrefix("128.0.0.0/1"),
	}
	if family == unix.AF_INET6 {
		prefixes = []netip.Prefix{
			netip.MustParsePrefix("::/1"),
			netip.MustParsePrefix("8000::/1"),
		}
	}
	scope := netlink.Scope(unix.RT_SCOPE_HOST)
	if family == unix.AF_INET6 {
		scope = netlink.Scope(unix.RT_SCOPE_UNIVERSE)
	}
	routes := make([]netlink.Route, 0, len(prefixes))
	for _, prefix := range prefixes {
		routes = append(routes, netlink.Route{
			LinkIndex: loopbackIndex,
			Family:    family,
			Dst: &net.IPNet{
				IP:   net.IP(prefix.Addr().AsSlice()),
				Mask: net.CIDRMask(prefix.Bits(), prefix.Addr().BitLen()),
			},
			Scope:    scope,
			Table:    table,
			Type:     unix.RTN_LOCAL,
			Protocol: netlink.RouteProtocol(unix.RTPROT_STATIC),
		})
	}
	return routes
}

func tcPolicyRule(family int) *netlink.Rule {
	return tcPolicyRuleFor(family, commonEBPF.DefaultTCRoutingMark, tcPolicyRoutingTable, tcPolicyRoutingPriority)
}

func tcPolicyRuleFor(family int, mark uint32, table, priority int) *netlink.Rule {
	rule := netlink.NewRule()
	rule.Priority = priority
	rule.Family = family
	rule.Table = table
	rule.Mark = mark
	rule.MarkSet = true
	rule.Mask = int(mark)
	return rule
}

type tcPolicyIdentifiers struct {
	mark     uint32
	table    int
	priority int
}

func allocateTCPolicyIdentifiers(loopbackIndex int, families []int) (tcPolicyIdentifiers, error) {
	usedTables := make(map[int]bool)
	usedPriorities := make(map[int]bool)
	var usedMarkBits uint32
	allFamilies := []int{unix.AF_INET, unix.AF_INET6}
	for _, family := range allFamilies {
		routes, err := netlink.RouteList(nil, family)
		if err != nil {
			if family == unix.AF_INET6 && (errors.Is(err, unix.EAFNOSUPPORT) || errors.Is(err, unix.EOPNOTSUPP)) {
				continue
			}
			return tcPolicyIdentifiers{}, E.Cause(err, "inspect TC eBPF routes")
		}
		for _, route := range routes {
			if route.Table > 0 {
				usedTables[route.Table] = true
			}
		}
		rules, err := netlink.RuleList(family)
		if err != nil {
			if family == unix.AF_INET6 && (errors.Is(err, unix.EAFNOSUPPORT) || errors.Is(err, unix.EOPNOTSUPP)) {
				continue
			}
			return tcPolicyIdentifiers{}, E.Cause(err, "inspect TC eBPF policy rules")
		}
		for _, rule := range rules {
			if rule.Table > 0 {
				usedTables[rule.Table] = true
			}
			if rule.Priority > 0 {
				usedPriorities[rule.Priority] = true
			}
			usedMarkBits |= tcPolicyRuleMarkBits(rule)
		}
	}
	preferred := tcPolicyIdentifiers{
		mark:     commonEBPF.DefaultTCRoutingMark,
		table:    tcPolicyRoutingTable,
		priority: tcPolicyRoutingPriority,
	}
	managed := true
	managedStateFound := false
	for _, family := range families {
		routes, err := netlink.RouteListFiltered(family, &netlink.Route{Table: preferred.table}, netlink.RT_FILTER_TABLE)
		if err != nil {
			return tcPolicyIdentifiers{}, E.Cause(err, "inspect TC eBPF policy state")
		}
		expectedRoutes := tcPolicyRoutesForTable(loopbackIndex, family, preferred.table)
		for _, route := range routes {
			if !matchesTCPolicyRoute(route, expectedRoutes) {
				managed = false
				break
			}
			managedStateFound = true
		}
		rules, err := netlink.RuleList(family)
		if err != nil {
			return tcPolicyIdentifiers{}, E.Cause(err, "inspect TC eBPF policy state")
		}
		for _, rule := range rules {
			if rule.Table != preferred.table {
				continue
			}
			if matchesTCPolicyRule(rule, *tcPolicyRuleFor(family, preferred.mark, preferred.table, preferred.priority)) {
				managedStateFound = true
				break
			}
			managed = false
			break
		}
	}
	if managed && managedStateFound {
		return preferred, nil
	}
	identifiers := tcPolicyIdentifiers{}
	for bit := uint(30); bit >= 16; bit-- {
		candidate := uint32(1) << bit
		if usedMarkBits&candidate == 0 {
			identifiers.mark = candidate
			break
		}
	}
	if identifiers.mark == 0 {
		return tcPolicyIdentifiers{}, E.New("no unused TC eBPF routing mark is available")
	}
	for table := tcPolicyRoutingTable; table <= tcPolicyTableMax; table++ {
		if !usedTables[table] {
			identifiers.table = table
			break
		}
	}
	if identifiers.table == 0 {
		for table := tcPolicyTableMin; table < tcPolicyRoutingTable; table++ {
			if !usedTables[table] {
				identifiers.table = table
				break
			}
		}
	}
	if identifiers.table == 0 {
		return tcPolicyIdentifiers{}, E.New("no unused TC eBPF routing table is available")
	}
	for priority := tcPolicyRoutingPriority; priority <= tcPolicyPriorityMax; priority++ {
		if !usedPriorities[priority] {
			identifiers.priority = priority
			break
		}
	}
	if identifiers.priority == 0 {
		for priority := tcPolicyPriorityMin; priority < tcPolicyRoutingPriority; priority++ {
			if !usedPriorities[priority] {
				identifiers.priority = priority
				break
			}
		}
	}
	if identifiers.priority == 0 {
		return tcPolicyIdentifiers{}, E.New("no unused TC eBPF policy priority is available")
	}
	return identifiers, nil
}

func tcPolicyRuleMarkBits(rule netlink.Rule) uint32 {
	if rule.Mask >= 0 {
		return rule.Mark | uint32(rule.Mask)
	}
	if rule.MarkSet || rule.Mark != 0 {
		// A fwmark rule without FRA_FWMASK matches the full mark value.
		return ^uint32(0)
	}
	return 0
}

func matchesTCPolicyRoute(route netlink.Route, expected []netlink.Route) bool {
	for _, candidate := range expected {
		if route.LinkIndex == candidate.LinkIndex &&
			route.Family == candidate.Family &&
			route.Table == candidate.Table &&
			route.Type == candidate.Type &&
			route.Scope == candidate.Scope &&
			routeDestination(route.Dst) == routeDestination(candidate.Dst) {
			return true
		}
	}
	return false
}

func routeDestination(destination *net.IPNet) netip.Prefix {
	if destination == nil {
		return netip.Prefix{}
	}
	bits, addressBits := destination.Mask.Size()
	address, loaded := netip.AddrFromSlice(destination.IP)
	if !loaded || bits < 0 {
		return netip.Prefix{}
	}
	address = address.Unmap()
	if address.BitLen() != addressBits {
		return netip.Prefix{}
	}
	return netip.PrefixFrom(address, bits).Masked()
}

func matchesTCPolicyRule(rule netlink.Rule, expected netlink.Rule) bool {
	return rule.Priority == expected.Priority &&
		rule.Family == expected.Family &&
		rule.Table == expected.Table &&
		rule.Mark == expected.Mark &&
		rule.Mask == expected.Mask
}

func tcPolicyDeleteIgnored(err error) bool {
	return err == nil || errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ESRCH)
}

func (r *tcPolicyRouting) Close() error {
	if r == nil {
		return nil
	}
	var closeErr error
	for index := range slices.Backward(r.rules) {
		if err := netlink.RuleDel(r.rules[index]); !tcPolicyDeleteIgnored(err) {
			closeErr = E.Errors(closeErr, err)
		}
	}
	r.rules = nil
	for index := range slices.Backward(r.routes) {
		if err := netlink.RouteDel(&r.routes[index]); !tcPolicyDeleteIgnored(err) {
			closeErr = E.Errors(closeErr, err)
		}
	}
	r.routes = nil
	if r.lock != nil {
		closeErr = E.Errors(closeErr, r.lock.Close())
		r.lock = nil
	}
	return closeErr
}
