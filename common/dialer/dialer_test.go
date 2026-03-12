package dialer

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

type innerResolverTestManager struct {
	adapter.DNSTransportManager
	transport adapter.DNSTransport
}

func (m innerResolverTestManager) Transport(tag string) (adapter.DNSTransport, bool) {
	return m.transport, tag == "inner"
}

type innerResolverTestTransport struct{ adapter.DNSTransport }

type innerResolverTestNetwork struct{ adapter.NetworkManager }

func (innerResolverTestNetwork) DefaultOptions() adapter.NetworkOptions {
	return adapter.NetworkOptions{DomainResolver: "outer"}
}

func TestInnerDNSQueryOptionsPreserveDNSRouting(t *testing.T) {
	ctx := service.ContextWith[adapter.NetworkManager](context.Background(), innerResolverTestNetwork{})
	ctx = service.ContextWith[adapter.DNSTransportManager](ctx, innerResolverTestManager{})
	for _, resolver := range []*option.DomainResolveOptions{nil, {}, {Strategy: option.DomainStrategy(C.DomainStrategyIPv4Only)}} {
		options, err := NewInnerDNSQueryOptions(ctx, resolver)
		require.NoError(t, err)
		require.Equal(t, adapter.DNSQueryOptions{}, options)
	}
}

func TestInnerDNSQueryOptionsExplicitResolver(t *testing.T) {
	transport := &innerResolverTestTransport{}
	ctx := service.ContextWith[adapter.DNSTransportManager](context.Background(), innerResolverTestManager{transport: transport})
	ctx = service.ContextWith[adapter.NetworkManager](ctx, innerResolverTestNetwork{})
	ttl := uint32(42)
	subnet := badoption.Prefixable(netip.MustParsePrefix("192.0.2.0/24"))
	resolver := &option.DomainResolveOptions{
		Server: "inner", Strategy: option.DomainStrategy(C.DomainStrategyIPv6Only),
		DisableCache: true, DisableOptimisticCache: true, RewriteTTL: &ttl,
		Timeout: badoption.Duration(time.Second), ClientSubnet: &subnet,
	}
	options, err := NewInnerDNSQueryOptions(ctx, resolver)
	require.NoError(t, err)
	require.Equal(t, adapter.DNSQueryOptions{
		Transport: transport, Strategy: C.DomainStrategyIPv6Only,
		DisableCache: true, DisableOptimisticCache: true, RewriteTTL: &ttl,
		Timeout: time.Second, ClientSubnet: netip.Prefix(subnet),
	}, options)
	resolver.Server = "missing"
	_, err = NewInnerDNSQueryOptions(ctx, resolver)
	require.ErrorContains(t, err, "domain resolver not found: missing")
}
