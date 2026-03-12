package masque

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

type resolverTestRouter struct {
	adapter.DNSRouter
	lookup func(string, adapter.DNSQueryOptions) ([]netip.Addr, error)
}

func (r resolverTestRouter) Lookup(_ context.Context, domain string, options adapter.DNSQueryOptions) ([]netip.Addr, error) {
	return r.lookup(domain, options)
}

type resolverTestManager struct {
	adapter.DNSTransportManager
}

func (resolverTestManager) Transport(string) (adapter.DNSTransport, bool) {
	return nil, false
}

func TestServerInnerResolver(t *testing.T) {
	ttl := uint32(42)
	for _, options := range []adapter.DNSQueryOptions{
		{},
		{
			Strategy: C.DomainStrategyIPv4Only, DisableCache: true,
			DisableOptimisticCache: true, RewriteTTL: &ttl, Timeout: time.Second,
			ClientSubnet: netip.MustParsePrefix("192.0.2.0/24"),
		},
	} {
		lookupErr := errors.New("lookup sentinel")
		calls := 0
		server := &ServerEndpoint{
			endpointBase:         endpointBase{logger: log.NewNOPFactory().Logger()},
			innerDNSQueryOptions: options,
			dnsRouter: resolverTestRouter{lookup: func(domain string, actual adapter.DNSQueryOptions) ([]netip.Addr, error) {
				calls++
				require.Equal(t, "target.invalid", domain)
				require.Equal(t, options, actual)
				return nil, lookupErr
			}},
		}
		server.started.Store(true)
		destination := M.ParseSocksaddr("target.invalid:443")
		_, err := server.DialContext(context.Background(), "tcp", destination)
		require.ErrorIs(t, err, lookupErr)
		_, _, err = server.ListenPacketWithDestination(context.Background(), destination)
		require.ErrorIs(t, err, lookupErr)
		_, err = server.resolve(context.Background(), destination.Fqdn)
		require.ErrorIs(t, err, lookupErr)
		require.Equal(t, 3, calls)
	}
}

func TestMissingInnerResolverFailsBeforeEndpointInitialization(t *testing.T) {
	ctx := service.ContextWith[adapter.DNSTransportManager](context.Background(), resolverTestManager{})
	options := option.MASQUEEndpointOptions{InnerDomainResolver: &option.DomainResolveOptions{Server: "missing"}}
	logger := log.NewNOPFactory().Logger()
	_, err := NewClientEndpoint(ctx, nil, logger, "client", option.MASQUEClientEndpointOptions{MASQUEEndpointOptions: options})
	require.ErrorContains(t, err, "inner domain resolver")
	_, err = NewServerEndpoint(ctx, nil, logger, "server", option.MASQUEServerEndpointOptions{MASQUEEndpointOptions: options})
	require.ErrorContains(t, err, "inner domain resolver")
}
