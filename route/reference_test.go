package route

import (
	"testing"

	"github.com/sagernet/sing-box/option"

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
	} {
		t.Run(name, func(t *testing.T) {
			require.Equal(t, []string{"outer", "inner"}, appendDomainResolver(nil, rawOptions))
		})
	}
}

func TestAppendDomainResolverIgnoresInnerResolverForSOCKS5(t *testing.T) {
	transports := appendDomainResolver(nil, &option.SOCKSOutboundOptions{
		Version:             "5",
		InnerDomainResolver: &option.DomainResolveOptions{Server: "inner"},
	})
	require.Empty(t, transports)
}
