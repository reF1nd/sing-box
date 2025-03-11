package route

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/adapter/provider"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestAppendDomainResolverIncludesInnerResolver(t *testing.T) {
	outerResolver := &option.DomainResolveOptions{Server: "outer"}
	innerResolver := &option.DomainResolveOptions{Server: "inner"}
	dialerOptions := option.DialerOptions{
		AbstractDialerOptions: option.AbstractDialerOptions{
			DomainResolver: outerResolver,
		},
	}

	for name, rawOptions := range map[string]any{
		"socks4": &option.SOCKSOutboundOptions{
			DialerOptions:       dialerOptions,
			Version:             "4",
			InnerDomainResolver: innerResolver,
		},
		"wireguard": &option.WireGuardEndpointOptions{
			DialerOptions:       dialerOptions,
			InnerDomainResolver: innerResolver,
		},
		"tailscale": &option.TailscaleEndpointOptions{
			DialerOptions:       dialerOptions,
			InnerDomainResolver: innerResolver,
		},
		"openconnect": &option.OpenConnectEndpointOptions{
			DialerOptions:       dialerOptions,
			InnerDomainResolver: innerResolver,
		},
		"openvpn-client": &option.OpenVPNClientEndpointOptions{
			DialerOptions: dialerOptions,
			OpenVPNEndpointOptions: option.OpenVPNEndpointOptions{
				InnerDomainResolver: innerResolver,
			},
		},
		"masque-client": &option.MASQUEClientEndpointOptions{
			DialerOptions: dialerOptions,
			MASQUEEndpointOptions: option.MASQUEEndpointOptions{
				InnerDomainResolver: innerResolver,
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			require.Equal(t, []string{"outer", "inner"}, appendDomainResolver(nil, rawOptions))
		})
	}
}

func TestAppendDomainResolverWithoutDialerOptions(t *testing.T) {
	options := &option.OpenVPNServerEndpointOptions{
		OpenVPNEndpointOptions: option.OpenVPNEndpointOptions{
			InnerDomainResolver: &option.DomainResolveOptions{Server: "inner"},
		},
	}
	require.Equal(t, []string{"inner"}, appendDomainResolver(nil, options))
	options.InnerDomainResolver = nil
	require.Empty(t, appendDomainResolver(nil, options))
	masqueOptions := &option.MASQUEServerEndpointOptions{
		MASQUEEndpointOptions: option.MASQUEEndpointOptions{
			InnerDomainResolver: &option.DomainResolveOptions{Server: "inner"},
		},
	}
	require.Equal(t, []string{"inner"}, appendDomainResolver(nil, masqueOptions))
	masqueOptions.InnerDomainResolver = nil
	require.Empty(t, appendDomainResolver(nil, masqueOptions))
}

func TestAppendDomainResolverIgnoresInnerResolverForSOCKS5(t *testing.T) {
	transports := appendDomainResolver(nil, &option.SOCKSOutboundOptions{
		Version:             "5",
		InnerDomainResolver: &option.DomainResolveOptions{Server: "inner"},
	})
	require.Empty(t, transports)
}

func TestNewReferenceManagerUsesIndexTagsForUntaggedStaticNodes(t *testing.T) {
	refManager := NewReferenceManager(context.Background(), log.NewNOPFactory().Logger(), option.Options{
		Outbounds: []option.Outbound{
			{
				Type: "socks",
				Options: &option.SOCKSOutboundOptions{
					Version: "4",
					DialerOptions: option.DialerOptions{
						AbstractDialerOptions: option.AbstractDialerOptions{
							DomainResolver: &option.DomainResolveOptions{Server: "dns-out-outer"},
						},
					},
					InnerDomainResolver: &option.DomainResolveOptions{Server: "dns-out-inner"},
				},
			},
		},
		Endpoints: []option.Endpoint{
			{
				Type: "wireguard",
				Options: &option.WireGuardEndpointOptions{
					DialerOptions: option.DialerOptions{
						AbstractDialerOptions: option.AbstractDialerOptions{
							DomainResolver: &option.DomainResolveOptions{Server: "dns-ep-outer"},
						},
					},
					InnerDomainResolver: &option.DomainResolveOptions{Server: "dns-ep-inner"},
				},
			},
		},
	})
	require.Equal(t, []string{"dns-out-outer", "dns-out-inner"}, refManager.domainResolvers[domainResolverKey{tag: "0"}])
	require.Equal(t, []string{"dns-ep-outer", "dns-ep-inner"}, refManager.domainResolvers[domainResolverKey{tag: "0", endpoint: true}])
	require.NotContains(t, refManager.domainResolvers, domainResolverKey{tag: ""})
	require.NotContains(t, refManager.domainResolvers, domainResolverKey{tag: "", endpoint: true})
}

func TestAppendDomainResolverIncludesBridgeResolver(t *testing.T) {
	options := &option.BridgeOutboundOptions{DomainResolver: &option.DomainResolveOptions{Server: "bridge-dns"}}
	require.Equal(t, []string{"bridge-dns"}, appendDomainResolver(nil, options))
	options.DomainResolver = nil
	require.Empty(t, appendDomainResolver(nil, options))
}

type testIdleDNSTransport struct {
	adapter.DNSTransport
	tag      string
	keepIdle atomic.Bool
}

func (t *testIdleDNSTransport) Type() string                           { return "test" }
func (t *testIdleDNSTransport) Tag() string                            { return t.tag }
func (t *testIdleDNSTransport) Dependencies() []string                 { return nil }
func (t *testIdleDNSTransport) Start(adapter.StartStage, *adapter.Scope) error { return nil }
func (t *testIdleDNSTransport) Close() error                           { return nil }
func (t *testIdleDNSTransport) Reset()                                 {}
func (t *testIdleDNSTransport) Exchange(context.Context, *dns.Msg) (*dns.Msg, error) {
	return nil, nil
}
func (t *testIdleDNSTransport) CloseIdleConnections()             {}
func (t *testIdleDNSTransport) SetKeepIdleConnections(keep bool)  { t.keepIdle.Store(keep) }

type testRefDNSTransportManager struct {
	adapter.DNSTransportManager
	transports map[string]*testIdleDNSTransport
	defaultTag string
}

func (m *testRefDNSTransportManager) Transports() []adapter.DNSTransport {
	result := make([]adapter.DNSTransport, 0, len(m.transports))
	for _, transport := range m.transports {
		result = append(result, transport)
	}
	return result
}

func (m *testRefDNSTransportManager) Transport(tag string) (adapter.DNSTransport, bool) {
	transport, loaded := m.transports[tag]
	return transport, loaded
}

func (m *testRefDNSTransportManager) Default() adapter.DNSTransport {
	return m.transports[m.defaultTag]
}

type testRefInboundManager struct{ adapter.InboundManager }

func (*testRefInboundManager) Inbounds() []adapter.Inbound { return nil }

type testRefServiceManager struct{ adapter.ServiceManager }

func (*testRefServiceManager) Services() []adapter.Service { return nil }

type testRefCertManager struct{ adapter.CertificateProviderManager }

func (*testRefCertManager) CertificateProviders() []adapter.CertificateProviderService { return nil }

type testRefNetworkManager struct{ adapter.NetworkManager }

func (*testRefNetworkManager) DefaultOptions() adapter.NetworkOptions { return adapter.NetworkOptions{} }

type testRefHTTPClientManager struct{ adapter.HTTPClientManager }

type testRefDynamicNode struct {
	outbound.Adapter
}

func (*testRefDynamicNode) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, net.ErrClosed
}

func (*testRefDynamicNode) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, net.ErrClosed
}

type testRefDynamicEndpoint struct {
	*testRefDynamicNode
}

func (*testRefDynamicEndpoint) IsEndpoint() {}
func (*testRefDynamicEndpoint) Start(adapter.StartStage, *adapter.Scope) error {
	return nil
}

func TestReferenceManagerTracksDynamicProviderResolvers(t *testing.T) {
	ctx := service.ContextWithPtr(context.Background(), urltest.NewHistoryStorage())
	factory := log.NewNOPFactory()
	logger := factory.Logger()

	outRegistry := outbound.NewRegistry()
	outbound.Register[option.SOCKSOutboundOptions](outRegistry, "socks", func(_ context.Context, _ adapter.Router, _ log.ContextLogger, tag string, _ option.SOCKSOutboundOptions) (adapter.Outbound, error) {
		return &testRefDynamicNode{Adapter: outbound.NewAdapter("socks", tag, []string{"tcp"}, nil)}, nil
	})
	epRegistry := endpoint.NewRegistry()
	endpoint.Register[option.WireGuardEndpointOptions](epRegistry, "wireguard", func(_ context.Context, _ adapter.Router, _ log.ContextLogger, tag string, _ option.WireGuardEndpointOptions) (adapter.Endpoint, error) {
		return &testRefDynamicEndpoint{testRefDynamicNode: &testRefDynamicNode{Adapter: outbound.NewAdapter("wireguard", tag, []string{"tcp"}, nil)}}, nil
	})

	epManager := endpoint.NewManager(epRegistry)
	outManager := outbound.NewManager(outRegistry, epManager, "fallback")
	dnsDefault := &testIdleDNSTransport{tag: "dns-default"}
	dnsOuterA := &testIdleDNSTransport{tag: "dns-outer-a"}
	dnsInnerA := &testIdleDNSTransport{tag: "dns-inner-a"}
	dnsOuterB := &testIdleDNSTransport{tag: "dns-outer-b"}
	dnsInnerB := &testIdleDNSTransport{tag: "dns-inner-b"}
	dnsEP := &testIdleDNSTransport{tag: "dns-ep"}
	dnsManager := &testRefDNSTransportManager{
		defaultTag: "dns-default",
		transports: map[string]*testIdleDNSTransport{
			"dns-default": dnsDefault,
			"dns-outer-a": dnsOuterA,
			"dns-inner-a": dnsInnerA,
			"dns-outer-b": dnsOuterB,
			"dns-inner-b": dnsInnerB,
			"dns-ep":      dnsEP,
		},
	}

	service.MustRegister[adapter.EndpointManager](ctx, epManager)
	service.MustRegister[adapter.OutboundManager](ctx, outManager)
	service.MustRegister[adapter.InboundManager](ctx, &testRefInboundManager{})
	service.MustRegister[adapter.ServiceManager](ctx, &testRefServiceManager{})
	service.MustRegister[adapter.DNSTransportManager](ctx, dnsManager)
	service.MustRegister[adapter.NetworkManager](ctx, &testRefNetworkManager{})
	service.MustRegister[adapter.HTTPClientManager](ctx, &testRefHTTPClientManager{})
	service.MustRegister[adapter.CertificateProviderManager](ctx, &testRefCertManager{})

	refManager := NewReferenceManager(ctx, logger, option.Options{
		Route: &option.RouteOptions{
			Rules: []option.Rule{
				{
					Type: "default",
					DefaultOptions: option.DefaultRule{
						RawDefaultRule: option.RawDefaultRule{Domain: []string{"example.com"}},
						RuleAction: option.RuleAction{
							Action:       "route",
							RouteOptions: option.RouteActionOptions{Outbound: "p/node"},
						},
					},
				},
			},
		},
	})
	service.MustRegister[adapter.DomainResolverReferenceTracker](ctx, refManager)

	scope := adapter.NewScope(ctx, logger)
	t.Cleanup(func() { require.NoError(t, scope.Close()) })
	require.NoError(t, outManager.Create(ctx, nil, logger, "fallback", "socks", &option.SOCKSOutboundOptions{}))
	for _, stage := range adapter.ListStartStages {
		require.NoError(t, scope.Start("endpoint", epManager, stage))
		require.NoError(t, scope.Start("outbound", outManager, stage))
		require.NoError(t, scope.Start("reference", refManager, stage))
	}

	p := provider.NewAdapter(ctx, nil, outManager, epManager, factory, logger, "p", "inline", option.ProviderHealthCheckOptions{})
	require.NoError(t, p.Start())
	t.Cleanup(func() { require.NoError(t, p.Close()) })

	// 1. Add dynamic outbound (outer + inner resolvers) and dynamic endpoint (inner resolver).
	require.NoError(t, p.UpdateNodes(
		[]option.Outbound{{
			Type: "socks",
			Tag:  "node",
			Options: &option.SOCKSOutboundOptions{
				Version: "4",
				DialerOptions: option.DialerOptions{
					AbstractDialerOptions: option.AbstractDialerOptions{
						DomainResolver: &option.DomainResolveOptions{Server: "dns-outer-a"},
					},
				},
				InnerDomainResolver: &option.DomainResolveOptions{Server: "dns-inner-a"},
			},
		}},
		[]option.Endpoint{{
			Type: "wireguard",
			Tag:  "ep",
			Options: &option.WireGuardEndpointOptions{
				InnerDomainResolver: &option.DomainResolveOptions{Server: "dns-ep"},
			},
		}},
	))
	require.Eventually(t, func() bool {
		return dnsOuterA.keepIdle.Load() && dnsInnerA.keepIdle.Load() && dnsEP.keepIdle.Load() &&
			!dnsOuterB.keepIdle.Load() && !dnsInnerB.keepIdle.Load()
	}, time.Second, 5*time.Millisecond)

	// 2. Replace dynamic outbound with new outer/inner resolvers; old resolvers become unreferenced.
	require.NoError(t, p.UpdateNodes(
		[]option.Outbound{{
			Type: "socks",
			Tag:  "node",
			Options: &option.SOCKSOutboundOptions{
				Version: "4",
				DialerOptions: option.DialerOptions{
					AbstractDialerOptions: option.AbstractDialerOptions{
						DomainResolver: &option.DomainResolveOptions{Server: "dns-outer-b"},
					},
				},
				InnerDomainResolver: &option.DomainResolveOptions{Server: "dns-inner-b"},
			},
		}},
		[]option.Endpoint{{
			Type: "wireguard",
			Tag:  "ep",
			Options: &option.WireGuardEndpointOptions{
				InnerDomainResolver: &option.DomainResolveOptions{Server: "dns-ep"},
			},
		}},
	))
	require.Eventually(t, func() bool {
		return !dnsOuterA.keepIdle.Load() && !dnsInnerA.keepIdle.Load() &&
			dnsOuterB.keepIdle.Load() && dnsInnerB.keepIdle.Load() && dnsEP.keepIdle.Load()
	}, time.Second, 5*time.Millisecond)

	// 3. Switch the same tag "node" from outbound -> endpoint (with dedicated inner resolver).
	// Removing the old outbound must not wipe the newly registered endpoint resolver.
	require.NoError(t, p.UpdateNodes(
		nil,
		[]option.Endpoint{{
			Type: "wireguard",
			Tag:  "node",
			Options: &option.WireGuardEndpointOptions{
				InnerDomainResolver: &option.DomainResolveOptions{Server: "dns-ep"},
			},
		}},
	))
	require.Eventually(t, func() bool {
		return !dnsOuterA.keepIdle.Load() && !dnsInnerA.keepIdle.Load() &&
			!dnsOuterB.keepIdle.Load() && !dnsInnerB.keepIdle.Load() &&
			dnsEP.keepIdle.Load()
	}, time.Second, 5*time.Millisecond)

	// 4. Switch the same tag "node" back from endpoint -> outbound.
	// Removing the old endpoint must not wipe the newly registered outbound resolvers.
	require.NoError(t, p.UpdateNodes(
		[]option.Outbound{{
			Type: "socks",
			Tag:  "node",
			Options: &option.SOCKSOutboundOptions{
				Version: "4",
				DialerOptions: option.DialerOptions{
					AbstractDialerOptions: option.AbstractDialerOptions{
						DomainResolver: &option.DomainResolveOptions{Server: "dns-outer-a"},
					},
				},
				InnerDomainResolver: &option.DomainResolveOptions{Server: "dns-inner-a"},
			},
		}},
		nil,
	))
	require.Eventually(t, func() bool {
		return dnsOuterA.keepIdle.Load() && dnsInnerA.keepIdle.Load() &&
			!dnsOuterB.keepIdle.Load() && !dnsInnerB.keepIdle.Load() &&
			!dnsEP.keepIdle.Load()
	}, time.Second, 5*time.Millisecond)

	// 5. Remove dynamic node; all dynamic resolvers become unreferenced.
	require.NoError(t, p.UpdateNodes(nil, nil))
	require.Eventually(t, func() bool {
		return !dnsOuterA.keepIdle.Load() && !dnsInnerA.keepIdle.Load() &&
			!dnsOuterB.keepIdle.Load() && !dnsInnerB.keepIdle.Load() && !dnsEP.keepIdle.Load()
	}, time.Second, 5*time.Millisecond)
}
