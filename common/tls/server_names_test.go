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
