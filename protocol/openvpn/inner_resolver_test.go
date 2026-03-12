package openvpn

import (
	"context"
	"errors"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
	"github.com/stretchr/testify/require"
	"net/netip"
	"testing"
	"time"
)

type missingInnerResolverManager struct{ adapter.DNSTransportManager }

func (*missingInnerResolverManager) Transport(string) (adapter.DNSTransport, bool) { return nil, false }

func TestEndpointRejectsUnknownInnerResolver(t *testing.T) {
	ctx := service.ContextWith[adapter.DNSTransportManager](t.Context(), &missingInnerResolverManager{})
	resolver := &option.DomainResolveOptions{Server: "missing-inner"}
	t.Run("client", func(t *testing.T) {
		endpoint, err := NewClientEndpoint(ctx, nil, nil, "test", option.OpenVPNClientEndpointOptions{OpenVPNEndpointOptions: option.OpenVPNEndpointOptions{InnerDomainResolver: resolver}})
		require.Nil(t, endpoint)
		require.EqualError(t, err, "inner domain resolver: domain resolver not found: missing-inner")
	})
	t.Run("server", func(t *testing.T) {
		endpoint, err := NewServerEndpoint(ctx, nil, nil, "test", option.OpenVPNServerEndpointOptions{OpenVPNEndpointOptions: option.OpenVPNEndpointOptions{InnerDomainResolver: resolver}})
		require.Nil(t, endpoint)
		require.EqualError(t, err, "inner domain resolver: domain resolver not found: missing-inner")
	})
}

type innerResolverRouter struct {
	adapter.DNSRouter
	t     *testing.T
	want  adapter.DNSQueryOptions
	err   error
	calls int
}

func (r *innerResolverRouter) Lookup(_ context.Context, domain string, options adapter.DNSQueryOptions) ([]netip.Addr, error) {
	require.Equal(r.t, "destination.example", domain)
	require.Equal(r.t, r.want, options)
	r.calls++
	return nil, r.err
}

func TestServerDestinationLookupUsesInnerResolver(t *testing.T) {
	ttl := uint32(60)
	for name, queryOptions := range map[string]adapter.DNSQueryOptions{
		"default":    {},
		"configured": {Transport: &struct{ adapter.DNSTransport }{}, Strategy: C.DomainStrategyIPv4Only, DisableCache: true, RewriteTTL: &ttl, Timeout: time.Second, ClientSubnet: netip.MustParsePrefix("192.0.2.0/24")},
	} {
		t.Run(name, func(t *testing.T) {
			lookupErr := errors.New("lookup stopped before dialing")
			router := &innerResolverRouter{t: t, want: queryOptions, err: lookupErr}
			endpoint := &ServerEndpoint{endpointBase: endpointBase{logger: log.NewNOPFactory().Logger()}, dnsRouter: router, innerDNSQueryOptions: queryOptions}
			endpoint.started.Store(true)
			destination := M.ParseSocksaddr("destination.example:443")
			_, err := endpoint.DialContext(t.Context(), N.NetworkTCP, destination)
			require.ErrorIs(t, err, lookupErr)
			_, _, err = endpoint.ListenPacketWithDestination(t.Context(), destination)
			require.ErrorIs(t, err, lookupErr)
			require.Equal(t, 2, router.calls)
		})
	}
}
