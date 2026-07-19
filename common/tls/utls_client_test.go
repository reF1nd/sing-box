//go:build with_utls

package tls

import (
	"context"
	"net"
	"testing"

	tf "github.com/sagernet/sing-box/common/tlsfragment"
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

// Guards the wrap gate in UTLSClientConfig.Client(): tf.Conn must wrap the
// underlying connection whenever either `fragment` or `record_fragment` is
// set. Mirrors the STDClientConfig gate tests to keep both code paths in
// lockstep.

func newUTLSClientConfigForGateTest(fragment, recordFragment bool) *UTLSClientConfig {
	return &UTLSClientConfig{
		ctx:            context.Background(),
		config:         &utls.Config{ServerName: "example.com", InsecureSkipVerify: true},
		id:             utls.HelloChrome_Auto,
		fragment:       fragment,
		recordFragment: recordFragment,
	}
}

func TestUTLSClient_Client_NoFragment_DoesNotWrap(t *testing.T) {
	t.Parallel()
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	wrapped, err := newUTLSClientConfigForGateTest(false, false).Client(client)
	require.NoError(t, err)
	_, isTF := wrapped.NetConn().(*tf.Conn)
	require.False(t, isTF, "no fragment flags: must not wrap with tf.Conn")
}

func TestUTLSClient_Client_FragmentOnly_Wraps(t *testing.T) {
	t.Parallel()
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	wrapped, err := newUTLSClientConfigForGateTest(true, false).Client(client)
	require.NoError(t, err)
	_, isTF := wrapped.NetConn().(*tf.Conn)
	require.True(t, isTF, "fragment=true: must wrap with tf.Conn")
}

func TestUTLSClient_Client_RecordFragmentOnly_Wraps(t *testing.T) {
	t.Parallel()
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	wrapped, err := newUTLSClientConfigForGateTest(false, true).Client(client)
	require.NoError(t, err)
	_, isTF := wrapped.NetConn().(*tf.Conn)
	require.True(t, isTF, "record_fragment=true: must wrap with tf.Conn")
}

func TestUTLSClient_Client_BothFragment_Wraps(t *testing.T) {
	t.Parallel()
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	wrapped, err := newUTLSClientConfigForGateTest(true, true).Client(client)
	require.NoError(t, err)
	_, isTF := wrapped.NetConn().(*tf.Conn)
	require.True(t, isTF, "both fragment flags: must wrap with tf.Conn")
}
