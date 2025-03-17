package sniff_test

import (
	"bytes"
	"crypto/tls"
	"encoding/pem"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/sniff"
	sTLS "github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/bufio"

	"github.com/stretchr/testify/require"
)

func TestTLSClientHelloReportsECHOuterSNI(t *testing.T) {
	const site = "site.example"
	const publicName = "public.example"
	configPEM, _, err := sTLS.ECHKeygenDefault(publicName)
	require.NoError(t, err)
	config, _ := pem.Decode([]byte(configPEM))
	require.NotNil(t, config)
	var hello bytes.Buffer
	client := tls.Client(bufio.NewWriteOnlyConn(&hello), &tls.Config{
		ServerName: site, EncryptedClientHelloConfigList: config.Bytes,
	})
	require.Error(t, client.HandshakeContext(t.Context()))
	require.NotEmpty(t, hello.Bytes())

	known := adapter.InboundContext{Domain: site, ECHPublicName: publicName}
	require.NoError(t, sniff.TLSClientHello(t.Context(), &known, bytes.NewReader(hello.Bytes())))
	require.Equal(t, C.ProtocolTLS, known.Protocol)
	require.Equal(t, publicName, known.SniffHost)
	require.True(t, known.SniffHasECHExtension)
	require.Equal(t, site, known.Domain)

	hello.Reset()
	client = tls.Client(bufio.NewWriteOnlyConn(&hello), &tls.Config{ServerName: publicName})
	require.Error(t, client.HandshakeContext(t.Context()))
	require.NoError(t, sniff.TLSClientHello(t.Context(), &known, &hello))
	require.Equal(t, publicName, known.SniffHost)
	require.False(t, known.SniffHasECHExtension)
}
