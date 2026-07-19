//go:build with_utls

package tls

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"

	utls "github.com/metacubex/utls"
	"github.com/stretchr/testify/require"
)

func TestUTLSClientCertificateServerNameDoesNotChangeSNI(t *testing.T) {
	config, err := NewUTLSClient(context.Background(), logger.NOP(), "", option.OutboundTLSOptions{
		Enabled:               true,
		ServerName:            "sni.example",
		CertificateServerName: "certificate.example",
		UTLS: &option.OutboundUTLSOptions{
			Enabled:     true,
			Fingerprint: "chrome",
		},
	})
	require.NoError(t, err)
	uConfig := config.(*UTLSClientConfig).config
	require.Equal(t, "sni.example", uConfig.ServerName)
	require.Equal(t, "certificate.example", uConfig.InsecureServerNameToVerify)
}

func TestUTLSClientCertificateServerNameWithEmptySNI(t *testing.T) {
	config, err := NewUTLSClient(context.Background(), logger.NOP(), "server.example", option.OutboundTLSOptions{
		Enabled:               true,
		DisableSNI:            true,
		CertificateServerName: "certificate.example",
		UTLS: &option.OutboundUTLSOptions{
			Enabled:     true,
			Fingerprint: "chrome",
		},
	})
	require.NoError(t, err)
	uConfig := config.(*UTLSClientConfig).config
	require.Empty(t, uConfig.ServerName)
	require.Equal(t, "certificate.example", uConfig.InsecureServerNameToVerify)
}

func TestUTLSClientCertificateServerNameWithIPServerName(t *testing.T) {
	config, err := NewUTLSClient(context.Background(), logger.NOP(), "", option.OutboundTLSOptions{
		Enabled:               true,
		ServerName:            "192.0.2.1",
		CertificateServerName: "certificate.example",
		UTLS: &option.OutboundUTLSOptions{
			Enabled:     true,
			Fingerprint: "chrome",
		},
	})
	require.NoError(t, err)
	uConfig := config.(*UTLSClientConfig).config
	require.Equal(t, "192.0.2.1", uConfig.ServerName)
	require.Equal(t, "certificate.example", uConfig.InsecureServerNameToVerify)
	require.Zero(t, (&utls.SNIExtension{ServerName: uConfig.ServerName}).Len())
}
