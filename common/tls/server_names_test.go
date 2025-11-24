package tls

import (
	"context"
	stdtls "crypto/tls"
	"testing"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"

	"github.com/stretchr/testify/require"
)

func TestServerNamesPolicy(t *testing.T) {
	for _, test := range []struct {
		name    string
		options option.InboundTLSOptions
		allowed []string
		denied  []string
	}{
		{"single", option.InboundTLSOptions{ServerName: "one.example", RejectUnknownSNI: true}, []string{"one.example"}, []string{"", "two.example"}},
		{"multiple", option.InboundTLSOptions{ServerNames: []string{"one.example", "two.example"}, RejectUnknownSNI: true}, []string{"one.example", "two.example"}, []string{"", "other.example"}},
		{"no_names", option.InboundTLSOptions{RejectUnknownSNI: true}, []string{""}, []string{"one.example"}},
		{"disabled", option.InboundTLSOptions{ServerNames: []string{"one.example"}}, []string{"", "other.example"}, nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			test.options.Enabled = true
			test.options.Insecure = true
			config, err := NewSTDServer(context.Background(), logger.NOP(), test.options)
			require.NoError(t, err)
			for _, candidate := range []Config{config, config.Clone()} {
				stdConfig, err := candidate.STDConfig()
				require.NoError(t, err)
				for _, name := range test.allowed {
					_, err = stdConfig.GetConfigForClient(&stdtls.ClientHelloInfo{ServerName: name})
					require.NoError(t, err)
				}
				for _, name := range test.denied {
					_, err = stdConfig.GetConfigForClient(&stdtls.ClientHelloInfo{ServerName: name})
					require.Error(t, err)
				}
			}
		})
	}
	_, err := NewSTDServer(context.Background(), logger.NOP(), option.InboundTLSOptions{
		Enabled: true, ServerName: "one.example", ServerNames: []string{"two.example"},
	})
	require.EqualError(t, err, "server_name and server_names cannot be configured at the same time")
}

type stubACMEProvider struct {
	protos []string
}

func (p *stubACMEProvider) Start() error                                               { return nil }
func (p *stubACMEProvider) Close() error                                               { return nil }
func (p *stubACMEProvider) GetCertificate(*stdtls.ClientHelloInfo) (*stdtls.Certificate, error) {
	return nil, nil
}
func (p *stubACMEProvider) GetACMENextProtos() []string { return p.protos }

func TestServerNamesPolicyWithACMEALPN(t *testing.T) {
	config, err := NewSTDServer(context.Background(), logger.NOP(), option.InboundTLSOptions{
		Enabled:          true,
		Insecure:         true,
		ALPN:             []string{"h2", "http/1.1"},
		ServerNames:      []string{"allowed.example"},
		RejectUnknownSNI: true,
	})
	require.NoError(t, err)
	stdServer := config.(*STDServerConfig)
	stdServer.certificateProvider = &stubACMEProvider{protos: []string{"acme-tls/1"}}

	stdConfig, err := config.STDConfig()
	require.NoError(t, err)

	// Listed SNI + pure acme-tls/1 challenge gets cloned config with acme-tls/1 ALPN.
	acmeCfg, err := stdConfig.GetConfigForClient(&stdtls.ClientHelloInfo{
		ServerName:      "allowed.example",
		SupportedProtos: []string{"acme-tls/1"},
	})
	require.NoError(t, err)
	require.Equal(t, []string{"acme-tls/1"}, acmeCfg.NextProtos)
	require.Equal(t, []string{"h2", "http/1.1"}, stdConfig.NextProtos)

	// Listed SNI + mixed ALPN stays on normal listener ALPN.
	mixedCfg, err := stdConfig.GetConfigForClient(&stdtls.ClientHelloInfo{
		ServerName:      "allowed.example",
		SupportedProtos: []string{"acme-tls/1", "h2"},
	})
	require.NoError(t, err)
	require.Equal(t, []string{"h2", "http/1.1"}, mixedCfg.NextProtos)

	// Unlisted SNI + pure acme-tls/1 is rejected by SNI whitelist before ACME branch.
	_, err = stdConfig.GetConfigForClient(&stdtls.ClientHelloInfo{
		ServerName:      "unlisted.example",
		SupportedProtos: []string{"acme-tls/1"},
	})
	require.Error(t, err)

	// Listed SNI + normal h2 after ACME challenge keeps normal ALPN.
	normalCfg, err := stdConfig.GetConfigForClient(&stdtls.ClientHelloInfo{
		ServerName:      "allowed.example",
		SupportedProtos: []string{"h2"},
	})
	require.NoError(t, err)
	require.Equal(t, []string{"h2", "http/1.1"}, normalCfg.NextProtos)
}
