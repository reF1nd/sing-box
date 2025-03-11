package parser

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/common/logger"

	"github.com/stretchr/testify/require"
)

func TestOverrideTLSOptionCertificatePinAndConflicts(t *testing.T) {
	pin := strings.Repeat("ab", 32)
	outbounds := overrideOutbounds([]option.Outbound{{
		Type: C.TypeTrojan,
		Options: &option.TrojanOutboundOptions{
			OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
				TLS: &option.OutboundTLSOptions{
					Enabled:    true,
					ServerName: "example.com",
					Insecure:   true,
				},
			},
		},
	}}, nil, &option.OverrideTLSOptions{
		CertificatePinSHA256: common.Ptr(pin),
	}, nil, "")
	tlsOpts := outbounds[0].Options.(*option.TrojanOutboundOptions).TLS
	require.Equal(t, pin, tlsOpts.CertificatePinSHA256)
	_, err := tls.NewClient(context.Background(), logger.NOP(), "example.com", *tlsOpts)
	require.NoError(t, err)

	// Overriding pin onto a node that already specifies certificate triggers TLS conflict validation.
	conflictOutbounds := overrideOutbounds([]option.Outbound{{
		Type: C.TypeTrojan,
		Options: &option.TrojanOutboundOptions{
			OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
				TLS: &option.OutboundTLSOptions{
					Enabled:     true,
					ServerName:  "example.com",
					Certificate: []string{"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----"},
				},
			},
		},
	}}, nil, &option.OverrideTLSOptions{
		CertificatePinSHA256: common.Ptr(pin),
	}, nil, "")
	_, err = tls.NewClient(context.Background(), logger.NOP(), "example.com", *conflictOutbounds[0].Options.(*option.TrojanOutboundOptions).TLS)
	require.ErrorContains(t, err, "conflict")

	// Disabling TLS via override clears TLS options cleanly.
	disabled := overrideTLSOption(&option.OutboundTLSOptions{Enabled: true, ServerName: "example.com"}, &option.OverrideTLSOptions{
		Enabled: common.Ptr(false),
	})
	require.Equal(t, &option.OutboundTLSOptions{}, disabled)
}

func TestOverrideDialerOptionPreservesDomainResolver(t *testing.T) {
	resolver := &option.DomainResolveOptions{Server: "dns-local"}
	timeout := badoption.Duration(5 * time.Second)
	var base option.DialerOptions
	base.DomainResolver = resolver
	got := overrideDialerOption(base, &option.OverrideDialerOptions{
		ConnectTimeout: &timeout,
	}, nil, "")
	require.Equal(t, resolver, got.DomainResolver)
	require.Equal(t, timeout, got.ConnectTimeout)

	newResolver := &option.DomainResolveOptions{Server: "dns-override"}
	got = overrideDialerOption(base, &option.OverrideDialerOptions{
		DomainResolver: newResolver,
	}, nil, "")
	require.Equal(t, newResolver, got.DomainResolver)
}

func TestParseBoxSubscriptionMalformedInputDoesNotPanic(t *testing.T) {
	for _, tc := range []struct {
		name    string
		payload string
		errPart string
	}{
		{"outbounds not array", `{"outbounds":"bad"}`, "expected array"},
		{"outbound element null", `{"outbounds":[null]}`, "outbound[0]"},
		{"outbound element scalar", `{"outbounds":[123]}`, "outbound[0]"},
		{"outbound missing type", `{"outbounds":[{"tag":"a"}]}`, "missing type in outbound[0]"},
		{"outbound non-string type", `{"outbounds":[{"type":123}]}`, "invalid type in outbound[0]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.NotPanics(t, func() {
				_, _, err := ParseBoxSubscription(context.Background(), tc.payload)
				require.ErrorContains(t, err, tc.errPart)
			})
		})
	}
}

func TestOverrideOutboundsAppliesTLSPinToNaive(t *testing.T) {
	t.Parallel()
	const pin = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	outbounds := []option.Outbound{
		{
			Type: C.TypeNaive,
			Tag:  "naive-node",
			Options: &option.NaiveOutboundOptions{
				ServerOptions: option.ServerOptions{
					Server:     "127.0.0.1",
					ServerPort: 443,
				},
				OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
					TLS: &option.OutboundTLSOptions{
						Enabled:    true,
						ServerName: "naive.example.com",
					},
				},
			},
		},
	}
	pinVal := pin
	overridden := overrideOutbounds(outbounds, nil, &option.OverrideTLSOptions{
		CertificatePinSHA256: &pinVal,
	}, []string{"naive-node"}, "sub")
	require.Len(t, overridden, 1)
	naiveOpts, ok := overridden[0].Options.(*option.NaiveOutboundOptions)
	require.True(t, ok)
	require.NotNil(t, naiveOpts.TLS)
	require.Equal(t, pin, naiveOpts.TLS.CertificatePinSHA256)
}

func TestOverrideEndpointsRewritesOpenConnectAndOpenVPNDetour(t *testing.T) {
	t.Parallel()
	timeout := badoption.Duration(7 * time.Second)
	endpoints := []option.Endpoint{
		{
			Type: C.TypeOpenConnect,
			Tag:  "oc-ep",
			Options: &option.OpenConnectEndpointOptions{
				DialerOptions: option.DialerOptions{
					Detour: "hop",
				},
			},
		},
		{
			Type: C.TypeOpenVPNClient,
			Tag:  "ovpn-ep",
			Options: &option.OpenVPNClientEndpointOptions{
				DialerOptions: option.DialerOptions{
					Detour: "hop",
				},
			},
		},
	}
	overridden := overrideEndpoints(endpoints, &option.OverrideDialerOptions{
		ConnectTimeout: &timeout,
	}, []string{"hop", "oc-ep", "ovpn-ep"}, "sub")
	require.Len(t, overridden, 2)

	ocOpts := overridden[0].Options.(*option.OpenConnectEndpointOptions)
	require.Equal(t, "sub/hop", ocOpts.Detour)
	require.Equal(t, timeout, ocOpts.ConnectTimeout)

	ovpnOpts := overridden[1].Options.(*option.OpenVPNClientEndpointOptions)
	require.Equal(t, "sub/hop", ovpnOpts.Detour)
	require.Equal(t, timeout, ovpnOpts.ConnectTimeout)
}
