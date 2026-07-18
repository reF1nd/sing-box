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

func TestAppendDomainResolverIncludesBridgeResolver(t *testing.T) {
	options := &option.BridgeOutboundOptions{DomainResolver: &option.DomainResolveOptions{Server: "bridge-dns"}}
	require.Equal(t, []string{"bridge-dns"}, appendDomainResolver(nil, options))
	options.DomainResolver = nil
	require.Empty(t, appendDomainResolver(nil, options))
}
