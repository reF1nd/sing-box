package tls

import (
	"context"
	stdtls "crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/common/logger"

	"github.com/stretchr/testify/require"
)

func TestSTDClientCertificateServerNameDoesNotChangeSNI(t *testing.T) {
	_, certificatePEM, err := GenerateCertificate(nil, nil, time.Now, "certificate.example", time.Now().Add(time.Hour))
	require.NoError(t, err)
	certificateBlock, _ := pem.Decode(certificatePEM)
	require.NotNil(t, certificateBlock)
	certificate, err := x509.ParseCertificate(certificateBlock.Bytes)
	require.NoError(t, err)

	config, err := NewSTDClient(context.Background(), logger.NOP(), "", option.OutboundTLSOptions{
		Enabled:               true,
		ServerName:            "sni.example",
		CertificateServerName: "certificate.example",
		Certificate:           badoption.Listable[string]{string(certificatePEM)},
	})
	require.NoError(t, err)
	stdConfig, err := config.STDConfig()
	require.NoError(t, err)
	require.Equal(t, "sni.example", stdConfig.ServerName)
	require.True(t, stdConfig.InsecureSkipVerify)
	require.NotNil(t, stdConfig.VerifyConnection)
	require.NoError(t, stdConfig.VerifyConnection(stdtls.ConnectionState{
		PeerCertificates: []*x509.Certificate{certificate},
	}))
}

func TestSTDClientCertificateServerNameWithEmptySNI(t *testing.T) {
	_, certificatePEM, err := GenerateCertificate(nil, nil, time.Now, "certificate.example", time.Now().Add(time.Hour))
	require.NoError(t, err)
	certificateBlock, _ := pem.Decode(certificatePEM)
	require.NotNil(t, certificateBlock)
	certificate, err := x509.ParseCertificate(certificateBlock.Bytes)
	require.NoError(t, err)

	config, err := NewSTDClient(context.Background(), logger.NOP(), "server.example", option.OutboundTLSOptions{
		Enabled:               true,
		DisableSNI:            true,
		CertificateServerName: "certificate.example",
		Certificate:           badoption.Listable[string]{string(certificatePEM)},
	})
	require.NoError(t, err)
	stdConfig, err := config.STDConfig()
	require.NoError(t, err)
	require.Empty(t, stdConfig.ServerName)
	require.NoError(t, stdConfig.VerifyConnection(stdtls.ConnectionState{
		PeerCertificates: []*x509.Certificate{certificate},
	}))
}

func TestSTDClientCertificateServerNameWithIPServerName(t *testing.T) {
	privateKeyPEM, certificatePEM, err := GenerateCertificate(nil, nil, time.Now, "certificate.example", time.Now().Add(time.Hour))
	require.NoError(t, err)
	serverCertificate, err := stdtls.X509KeyPair(certificatePEM, privateKeyPEM)
	require.NoError(t, err)

	config, err := NewSTDClient(context.Background(), logger.NOP(), "", option.OutboundTLSOptions{
		Enabled:               true,
		ServerName:            "192.0.2.1",
		CertificateServerName: "certificate.example",
		Certificate:           badoption.Listable[string]{string(certificatePEM)},
	})
	require.NoError(t, err)
	stdConfig, err := config.STDConfig()
	require.NoError(t, err)

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	deadline := time.Now().Add(5 * time.Second)
	require.NoError(t, clientConn.SetDeadline(deadline))
	require.NoError(t, serverConn.SetDeadline(deadline))
	clientTLS := stdtls.Client(clientConn, stdConfig)
	serverTLS := stdtls.Server(serverConn, &stdtls.Config{Certificates: []stdtls.Certificate{serverCertificate}})
	serverResult := make(chan error, 1)
	go func() {
		serverResult <- serverTLS.Handshake()
	}()
	require.NoError(t, clientTLS.Handshake())
	require.NoError(t, <-serverResult)
	require.Empty(t, serverTLS.ConnectionState().ServerName)
}
