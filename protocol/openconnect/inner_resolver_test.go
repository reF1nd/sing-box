package openconnect

import (
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/service"
	"github.com/stretchr/testify/require"
	"testing"
)

type missingInnerResolverManager struct{ adapter.DNSTransportManager }

func (*missingInnerResolverManager) Transport(string) (adapter.DNSTransport, bool) { return nil, false }

func TestEndpointRejectsUnknownInnerResolver(t *testing.T) {
	ctx := service.ContextWith[adapter.DNSTransportManager](t.Context(), &missingInnerResolverManager{})
	resolver := &option.DomainResolveOptions{Server: "missing-inner"}
	endpoint, err := NewEndpoint(ctx, nil, nil, "test", option.OpenConnectEndpointOptions{InnerDomainResolver: resolver})
	require.Nil(t, endpoint)
	require.EqualError(t, err, "inner domain resolver: domain resolver not found: missing-inner")
}
