package parser

import (
	"encoding/base64"
	"strings"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"

	"github.com/stretchr/testify/require"
)

func TestParseVMessLinkSNI(t *testing.T) {
	link := "vmess://" + base64.RawURLEncoding.EncodeToString([]byte(`{"add":"192.0.2.1","port":"443","id":"11111111-1111-1111-1111-111111111111","tls":"tls","sni":"example.com"}`))
	outbound, err := ParseSubscriptionLink(link)
	require.NoError(t, err)

	options := outbound.Options.(*option.VMessOutboundOptions)
	require.Equal(t, "192.0.2.1", options.Server)
	require.Equal(t, "example.com", options.TLS.ServerName)
}

func TestParseVMessLinkHostServerNameFallback(t *testing.T) {
	testCases := []struct {
		name       string
		link       string
		serverName string
	}{
		{
			"websocket host",
			`{"add":"192.0.2.1","port":"443","id":"11111111-1111-1111-1111-111111111111","tls":"tls","net":"ws","host":"example.com"}`,
			"example.com",
		},
		{
			"http2 host",
			`{"add":"192.0.2.1","port":"443","id":"11111111-1111-1111-1111-111111111111","tls":"tls","net":"h2","host":"example.com"}`,
			"example.com",
		},
		{
			"explicit sni",
			`{"add":"192.0.2.1","port":"443","id":"11111111-1111-1111-1111-111111111111","tls":"tls","net":"ws","host":"host.example","sni":"sni.example"}`,
			"sni.example",
		},
		{
			"domain server",
			`{"add":"server.example","port":"443","id":"11111111-1111-1111-1111-111111111111","tls":"tls","net":"ws","host":"host.example"}`,
			"server.example",
		},
		{
			"grpc host",
			`{"add":"192.0.2.1","port":"443","id":"11111111-1111-1111-1111-111111111111","tls":"tls","net":"grpc","host":"example.com"}`,
			"192.0.2.1",
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			link := "vmess://" + base64.RawURLEncoding.EncodeToString([]byte(testCase.link))
			outbound, err := ParseSubscriptionLink(link)
			require.NoError(t, err)

			options := outbound.Options.(*option.VMessOutboundOptions)
			require.Equal(t, testCase.serverName, options.TLS.ServerName)
		})
	}
}

func TestParseVLESSLinkHostServerNameFallback(t *testing.T) {
	const linkPrefix = "vless://11111111-1111-1111-1111-111111111111@"
	testCases := []struct {
		name       string
		link       string
		serverName string
	}{
		{
			"websocket host",
			"192.0.2.1:443?security=tls&type=ws&host=example.com",
			"example.com",
		},
		{
			"http host",
			"192.0.2.1:443?security=tls&type=http&host=example.com",
			"example.com",
		},
		{
			"explicit sni",
			"192.0.2.1:443?security=tls&type=ws&host=host.example&sni=sni.example",
			"sni.example",
		},
		{
			"domain server",
			"server.example:443?security=tls&type=ws&host=host.example",
			"server.example",
		},
		{
			"reality",
			"192.0.2.1:443?security=reality&type=ws&host=example.com",
			"192.0.2.1",
		},
		{
			"grpc host",
			"192.0.2.1:443?security=tls&type=grpc&host=example.com",
			"192.0.2.1",
		},
		{
			"host with port",
			"192.0.2.1:443?security=tls&type=ws&host=example.com%3A443",
			"192.0.2.1",
		},
		{
			"multiple http hosts",
			"192.0.2.1:443?security=tls&type=http&host=one.example%2Ctwo.example",
			"192.0.2.1",
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			outbound, err := ParseSubscriptionLink(linkPrefix + testCase.link)
			require.NoError(t, err)

			options := outbound.Options.(*option.VLESSOutboundOptions)
			require.Equal(t, testCase.serverName, options.TLS.ServerName)
		})
	}
}

func TestParseV2RayLinkHostServerNameFallbackRequiresTLS(t *testing.T) {
	vmessLink := "vmess://" + base64.RawURLEncoding.EncodeToString([]byte(`{"add":"192.0.2.1","port":"443","id":"11111111-1111-1111-1111-111111111111","net":"ws","host":"example.com"}`))
	vmessOutbound, err := ParseSubscriptionLink(vmessLink)
	require.NoError(t, err)
	require.Nil(t, vmessOutbound.Options.(*option.VMessOutboundOptions).TLS)

	vlessOutbound, err := ParseSubscriptionLink("vless://11111111-1111-1111-1111-111111111111@192.0.2.1:443?type=ws&host=example.com")
	require.NoError(t, err)
	require.Nil(t, vlessOutbound.Options.(*option.VLESSOutboundOptions).TLS)
}

func TestParseHysteria2LinkOptions(t *testing.T) {
	outbound, err := ParseSubscriptionLink("hysteria2://password@192.0.2.1:443?sni=example.com&pinSHA256=AA:BB&mport=40000-50000")
	require.NoError(t, err)

	options := outbound.Options.(*option.Hysteria2OutboundOptions)
	require.Equal(t, []string{"40000:50000"}, []string(options.ServerPorts))
	require.Equal(t, "example.com", options.TLS.ServerName)
	require.Equal(t, "AA:BB", options.TLS.CertificatePinSHA256)
}

func TestParseHysteria2LinkDisableSNI(t *testing.T) {
	validPin := strings.Repeat("ab", 32)
	testCases := []struct {
		name           string
		link           string
		wantDisableSNI bool
		wantServerName string
		wantPin        string
		wantInsecure   bool
	}{
		{
			name:           "hy2 disable_sni=1",
			link:           "hy2://password@node.example:443?disable_sni=1",
			wantDisableSNI: true,
			wantServerName: "node.example",
		},
		{
			name:           "hy2 disable_sni=true",
			link:           "hy2://password@node.example:443?disable_sni=true",
			wantDisableSNI: true,
			wantServerName: "node.example",
		},
		{
			name:           "hysteria2 disable_sni=1",
			link:           "hysteria2://password@node.example:443?disable_sni=1",
			wantDisableSNI: true,
			wantServerName: "node.example",
		},
		{
			name:           "hysteria2 disable_sni=true",
			link:           "hysteria2://password@node.example:443?disable_sni=true",
			wantDisableSNI: true,
			wantServerName: "node.example",
		},
		{
			name:           "default unset",
			link:           "hy2://password@node.example:443",
			wantDisableSNI: false,
			wantServerName: "node.example",
		},
		{
			name:           "disable_sni=0",
			link:           "hy2://password@node.example:443?disable_sni=0",
			wantDisableSNI: false,
			wantServerName: "node.example",
		},
		{
			name:           "disable_sni=false",
			link:           "hysteria2://password@node.example:443?disable_sni=false",
			wantDisableSNI: false,
			wantServerName: "node.example",
		},
		{
			name:           "disable_sni empty",
			link:           "hy2://password@node.example:443?disable_sni=",
			wantDisableSNI: false,
			wantServerName: "node.example",
		},
		{
			name:           "disable_sni uppercase TRUE ignored",
			link:           "hy2://password@node.example:443?disable_sni=TRUE",
			wantDisableSNI: false,
			wantServerName: "node.example",
		},
		{
			name:           "hyphenated disable-sni ignored",
			link:           "hy2://password@node.example:443?disable-sni=1",
			wantDisableSNI: false,
			wantServerName: "node.example",
		},
		{
			name:           "explicit sni preserved",
			link:           "hy2://password@192.0.2.1:443?sni=cert.example&disable_sni=1",
			wantDisableSNI: true,
			wantServerName: "cert.example",
		},
		{
			name:           "ip host without sni preserved",
			link:           "hy2://password@192.0.2.1:443?disable_sni=1",
			wantDisableSNI: true,
			wantServerName: "192.0.2.1",
		},
		{
			name:           "pinSHA256 preserved",
			link:           "hysteria2://password@192.0.2.1:443?sni=cert.example&pinSHA256=" + validPin + "&disable_sni=1",
			wantDisableSNI: true,
			wantServerName: "cert.example",
			wantPin:        validPin,
		},
		{
			name:           "insecure preserved",
			link:           "hy2://password@node.example:443?insecure=1&disable_sni=1",
			wantDisableSNI: true,
			wantServerName: "node.example",
			wantInsecure:   true,
		},
		{
			name:           "pinSHA256 and insecure both preserved",
			link:           "hy2://password@192.0.2.1:443?pinSHA256=" + validPin + "&insecure=1&disable_sni=1",
			wantDisableSNI: true,
			wantServerName: "192.0.2.1",
			wantPin:        validPin,
			wantInsecure:   true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			outbound, err := ParseSubscriptionLink(tc.link)
			require.NoError(t, err)
			require.Equal(t, C.TypeHysteria2, outbound.Type)

			options, ok := outbound.Options.(*option.Hysteria2OutboundOptions)
			require.True(t, ok)
			require.NotNil(t, options.TLS)
			require.True(t, options.TLS.Enabled)
			require.Equal(t, tc.wantDisableSNI, options.TLS.DisableSNI)
			require.Equal(t, tc.wantServerName, options.TLS.ServerName)
			require.Equal(t, tc.wantPin, options.TLS.CertificatePinSHA256)
			require.Equal(t, tc.wantInsecure, options.TLS.Insecure)
		})
	}
}

func TestParseSubscriptionHysteria2DisableSNIOverride(t *testing.T) {
	validPin := strings.Repeat("cd", 32)
	enabledLink := "hy2://password@192.0.2.1:443?sni=cert.example&pinSHA256=" + validPin + "&disable_sni=1#hy2-node"
	unsetLink := "hy2://password@192.0.2.1:443?sni=cert.example&pinSHA256=" + validPin + "#hy2-node"
	disabledLink := "hy2://password@192.0.2.1:443?sni=cert.example&pinSHA256=" + validPin + "&disable_sni=0#hy2-node"

	testCases := []struct {
		name           string
		link           string
		override       *option.OverrideTLSOptions
		wantDisableSNI bool
	}{
		{
			name:           "nil override keeps link disable_sni=1",
			link:           enabledLink,
			wantDisableSNI: true,
		},
		{
			name:           "empty override keeps link disable_sni=1",
			link:           enabledLink,
			override:       &option.OverrideTLSOptions{},
			wantDisableSNI: true,
		},
		{
			name:           "explicit false overrides link disable_sni=1",
			link:           enabledLink,
			override:       &option.OverrideTLSOptions{DisableSNI: common.Ptr(false)},
			wantDisableSNI: false,
		},
		{
			name:           "explicit true overrides unset link",
			link:           unsetLink,
			override:       &option.OverrideTLSOptions{DisableSNI: common.Ptr(true)},
			wantDisableSNI: true,
		},
		{
			name:           "explicit true overrides link disable_sni=0",
			link:           disabledLink,
			override:       &option.OverrideTLSOptions{DisableSNI: common.Ptr(true)},
			wantDisableSNI: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			outbounds, endpoints, err := ParseSubscription(t.Context(), tc.link, nil, tc.override, "p")
			require.NoError(t, err)
			require.Empty(t, endpoints)
			require.Len(t, outbounds, 1)
			require.Equal(t, C.TypeHysteria2, outbounds[0].Type)

			options := outbounds[0].Options.(*option.Hysteria2OutboundOptions)
			require.NotNil(t, options.TLS)
			require.True(t, options.TLS.Enabled)
			require.Equal(t, tc.wantDisableSNI, options.TLS.DisableSNI)
			require.Equal(t, "cert.example", options.TLS.ServerName)
			require.Equal(t, validPin, options.TLS.CertificatePinSHA256)
		})
	}
}
