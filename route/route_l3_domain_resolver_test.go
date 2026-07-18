package route

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	R "github.com/sagernet/sing-box/route/rule"
	tun "github.com/sagernet/sing-tun"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

func TestPreMatchFlowUsesSelectedOutboundDomainResolver(t *testing.T) {
	queryOptions := adapter.DNSQueryOptions{Strategy: C.DomainStrategyPreferIPv4}
	selectedOutbound := &testResolvingFlowOutbound{
		testFlowOutbound: &testFlowOutbound{outboundType: "wireguard", tag: "wg"},
		queryOptions:     queryOptions,
	}
	selector := &testOutboundGroup{now: selectedOutbound.Tag(), selected: selectedOutbound}
	dnsRouter := &testL3DNSRouter{addresses: []netip.Addr{netip.MustParseAddr("203.0.113.1")}}
	router := &Router{
		logger: log.NewNOPFactory().NewLogger("router"),
		outbound: &testL3OutboundManager{
			defaultOutbound: selector,
			outbounds:       map[string]adapter.Outbound{selectedOutbound.Tag(): selectedOutbound},
		},
		dns: dnsRouter,
	}
	metadata := &adapter.InboundContext{
		Network:     N.NetworkTCP,
		Source:      M.ParseSocksaddr("192.0.2.1:1234"),
		Destination: M.ParseSocksaddr("example.com:443"),
		FakeIP:      true,
	}

	result := router.preMatchFlow(context.Background(), metadata, M.ParseSocksaddr("198.18.0.1:443"), nil, "")

	require.Equal(t, adapter.PreMatchFlow, result.Action)
	require.Same(t, selectedOutbound, result.Outbound)
	require.Equal(t, netip.MustParseAddrPort("203.0.113.1:443"), result.Destination)
	require.Equal(t, "example.com", dnsRouter.domain)
	require.Equal(t, queryOptions, dnsRouter.options)
	require.Equal(t, []netip.Addr{netip.MustParseAddr("203.0.113.1")}, metadata.DestinationAddresses)
}

func TestPreMatchFlowRequiresExplicitResolveForOutboundWithoutDomainResolver(t *testing.T) {
	selectedOutbound := &testFlowOutbound{outboundType: "custom", tag: "custom"}
	dnsRouter := new(testL3DNSRouter)
	router := &Router{
		logger:   log.NewNOPFactory().NewLogger("router"),
		outbound: &testL3OutboundManager{defaultOutbound: selectedOutbound},
		dns:      dnsRouter,
	}
	metadata := &adapter.InboundContext{
		Network:     N.NetworkTCP,
		Source:      M.ParseSocksaddr("192.0.2.1:1234"),
		Destination: M.ParseSocksaddr("example.com:443"),
		FakeIP:      true,
	}

	result := router.preMatchFlow(context.Background(), metadata, M.ParseSocksaddr("198.18.0.1:443"), nil, "")

	require.Equal(t, adapter.PreMatchReject, result.Action)
	require.Zero(t, dnsRouter.lookupCount)
}

func TestPreMatchFlowKeepsExplicitResolveForResolvingOutbound(t *testing.T) {
	selectedOutbound := &testResolvingFlowOutbound{
		testFlowOutbound: &testFlowOutbound{outboundType: "wireguard", tag: "wg"},
		queryOptions:     adapter.DNSQueryOptions{Strategy: C.DomainStrategyIPv6Only},
	}
	dnsRouter := &testL3DNSRouter{addresses: []netip.Addr{netip.MustParseAddr("2001:db8::1")}}
	router := &Router{
		logger:   log.NewNOPFactory().NewLogger("router"),
		outbound: &testL3OutboundManager{defaultOutbound: selectedOutbound},
		dns:      dnsRouter,
	}
	metadata := &adapter.InboundContext{
		Network:              N.NetworkTCP,
		Source:               M.ParseSocksaddr("192.0.2.1:1234"),
		Destination:          M.ParseSocksaddr("example.com:443"),
		DestinationAddresses: []netip.Addr{netip.MustParseAddr("203.0.113.1")},
		FakeIP:               true,
	}

	result := router.preMatchFlow(context.Background(), metadata, M.ParseSocksaddr("198.18.0.1:443"), nil, "")

	require.Equal(t, adapter.PreMatchFlow, result.Action)
	require.Equal(t, netip.MustParseAddrPort("203.0.113.1:443"), result.Destination)
	require.Zero(t, dnsRouter.lookupCount)
}

func TestPreMatchFlowResolvesUDPFakeIPWithSelectedOutbound(t *testing.T) {
	selectedOutbound := &testResolvingFlowOutbound{
		testFlowOutbound: &testFlowOutbound{outboundType: "wireguard", tag: "wg"},
		queryOptions:     adapter.DNSQueryOptions{Strategy: C.DomainStrategyIPv4Only},
	}
	dnsRouter := &testL3DNSRouter{addresses: []netip.Addr{netip.MustParseAddr("203.0.113.1")}}
	router := &Router{
		logger:   log.NewNOPFactory().NewLogger("router"),
		outbound: &testL3OutboundManager{defaultOutbound: selectedOutbound},
		dns:      dnsRouter,
	}
	metadata := &adapter.InboundContext{
		Network:     N.NetworkUDP,
		Source:      M.ParseSocksaddr("192.0.2.1:1234"),
		Destination: M.ParseSocksaddr("example.com:443"),
		FakeIP:      true,
	}

	result := router.preMatchFlow(context.Background(), metadata, M.ParseSocksaddr("198.18.0.1:443"), nil, "")

	require.Equal(t, adapter.PreMatchFlow, result.Action)
	require.Equal(t, netip.MustParseAddrPort("203.0.113.1:443"), result.Destination)
	require.Equal(t, selectedOutbound.queryOptions, dnsRouter.options)
	require.Equal(t, 1, dnsRouter.lookupCount)
}

func TestPreMatchFlowResolvesSniffOverrideDestination(t *testing.T) {
	selectedOutbound := &testResolvingFlowOutbound{
		testFlowOutbound: &testFlowOutbound{outboundType: "wireguard", tag: "wg"},
		queryOptions:     adapter.DNSQueryOptions{Strategy: C.DomainStrategyIPv4Only},
	}
	dnsRouter := &testL3DNSRouter{addresses: []netip.Addr{netip.MustParseAddr("203.0.113.1")}}
	router := &Router{
		ctx:          context.Background(),
		logger:       log.NewNOPFactory().NewLogger("router"),
		outbound:     &testL3OutboundManager{defaultOutbound: selectedOutbound},
		dns:          dnsRouter,
		dnsTransport: new(testL3DNSTransportManager),
		rules: []adapter.Rule{
			&testL3Rule{action: new(R.RuleActionSniffOverrideDestination)},
		},
	}
	originalDestination := M.ParseSocksaddr("192.0.2.2:443")
	metadata := adapter.InboundContext{
		Network:     N.NetworkUDP,
		Source:      M.ParseSocksaddr("192.0.2.1:1234"),
		Destination: originalDestination,
		SniffHost:   "example.com",
	}

	result := router.PreMatch(metadata, nil)

	require.Equal(t, adapter.PreMatchFlow, result.Action)
	require.Equal(t, netip.MustParseAddrPort("203.0.113.1:443"), result.Destination)
	require.Equal(t, 1, dnsRouter.lookupCount)
}

type testL3DNSRouter struct {
	adapter.DNSRouter
	addresses   []netip.Addr
	domain      string
	options     adapter.DNSQueryOptions
	lookupCount int
}

type testL3DNSTransportManager struct {
	adapter.DNSTransportManager
}

func (m *testL3DNSTransportManager) FakeIP() adapter.FakeIPTransport {
	return nil
}

type testL3Rule struct {
	adapter.Rule
	action adapter.RuleAction
}

func (r *testL3Rule) Match(*adapter.InboundContext) bool {
	return true
}

func (r *testL3Rule) Disabled() bool {
	return false
}

func (r *testL3Rule) String() string {
	return ""
}

func (r *testL3Rule) Action() adapter.RuleAction {
	return r.action
}

func (r *testL3DNSRouter) Lookup(_ context.Context, domain string, options adapter.DNSQueryOptions) ([]netip.Addr, error) {
	r.lookupCount++
	r.domain = domain
	r.options = options
	return r.addresses, nil
}

func (r *testL3DNSRouter) LookupReverseMapping(netip.Addr) (string, bool) {
	return "", false
}

type testL3OutboundManager struct {
	adapter.OutboundManager
	defaultOutbound adapter.Outbound
	outbounds       map[string]adapter.Outbound
}

func (m *testL3OutboundManager) Default() adapter.Outbound {
	return m.defaultOutbound
}

func (m *testL3OutboundManager) Outbound(tag string) (adapter.Outbound, bool) {
	outbound, loaded := m.outbounds[tag]
	return outbound, loaded
}

type testOutboundGroup struct {
	adapter.Outbound
	now      string
	selected adapter.Outbound
}

func (g *testOutboundGroup) Now() string {
	return g.now
}

func (g *testOutboundGroup) All() []string {
	return []string{g.now}
}

func (g *testOutboundGroup) SelectPreMatchOutbound(_ *adapter.InboundContext, selectOutbound func(adapter.Outbound) (adapter.Outbound, adapter.PreMatchAction)) (adapter.Outbound, adapter.PreMatchAction) {
	return selectOutbound(g.selected)
}

type testFlowOutbound struct {
	outboundType string
	tag          string
}

func (o *testFlowOutbound) Type() string {
	return o.outboundType
}

func (o *testFlowOutbound) Tag() string {
	return o.tag
}

func (o *testFlowOutbound) Network() []string {
	return []string{N.NetworkTCP, N.NetworkUDP, N.NetworkICMP}
}

func (o *testFlowOutbound) Dependencies() []string {
	return nil
}

func (o *testFlowOutbound) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	panic("not implemented")
}

func (o *testFlowOutbound) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	panic("not implemented")
}

func (o *testFlowOutbound) PreMatchFlow(string, netip.Addr) adapter.PreMatchAction {
	return adapter.PreMatchFlow
}

func (o *testFlowOutbound) PortAddresses() (netip.Addr, netip.Addr) {
	return netip.Addr{}, netip.Addr{}
}

func (o *testFlowOutbound) PortMTU() uint32 {
	return 0
}

func (o *testFlowOutbound) AttachReturn(tun.Return) error {
	return nil
}

func (o *testFlowOutbound) DetachReturn(tun.Return) error {
	return nil
}

func (o *testFlowOutbound) WritePackets([][]byte) error {
	return nil
}

type testResolvingFlowOutbound struct {
	*testFlowOutbound
	queryOptions adapter.DNSQueryOptions
}

func (o *testResolvingFlowOutbound) FlowDomainResolveOptions() adapter.DNSQueryOptions {
	return o.queryOptions
}
