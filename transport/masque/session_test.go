package masque

import (
	"bytes"
	"testing"

	transportHTTP "github.com/sagernet/sing-box/transport/http"
	"github.com/sagernet/sing/common/buf"

	"github.com/stretchr/testify/require"
)

type limitedDatagramStream struct {
	transportHTTP.DatagramStream
}

func (*limitedDatagramStream) SendDatagram([]byte) error {
	return &transportHTTP.DatagramTooLargeError{MaxPayloadSize: 1200}
}

func TestInsufficientQUICMTUAllowsVersionFallback(t *testing.T) {
	current := &session{datagrams: &limitedDatagramStream{}}
	packet := buf.NewSize(PacketHeadroom + minimumLinkMTU)
	packet.Resize(PacketHeadroom, minimumLinkMTU)
	err := current.writePackets([]*buf.Buffer{packet})
	require.ErrorIs(t, err, transportHTTP.ErrHTTP3Unavailable)
	require.ErrorContains(t, err, "unable to carry 1280 bytes packets")
}

type ipPolicyDatagramStream struct {
	transportHTTP.DatagramStream
	bytes.Buffer
	calls       int
	unsupported bool
}

func (s *ipPolicyDatagramStream) Close() error                { return nil }
func (s *ipPolicyDatagramStream) Read(p []byte) (int, error)  { return s.Buffer.Read(p) }
func (s *ipPolicyDatagramStream) Write(p []byte) (int, error) { return s.Buffer.Write(p) }
func (s *ipPolicyDatagramStream) SendDatagram([]byte) error {
	panic("IP packet used ordinary DATAGRAM path")
}

func (s *ipPolicyDatagramStream) SendIPDatagram([]byte) error {
	s.calls++
	if s.unsupported {
		return transportHTTP.ErrDatagramUnsupported
	}
	return nil
}

func TestIPDatagramPolicyAndCapsuleFallback(t *testing.T) {
	for _, unsupported := range []bool{false, true} {
		stream := &ipPolicyDatagramStream{unsupported: unsupported}
		current := &session{stream: stream, datagrams: stream}
		packet := buf.NewSize(PacketHeadroom + minimumLinkMTU)
		packet.Resize(PacketHeadroom, minimumLinkMTU)
		require.NoError(t, current.writePackets([]*buf.Buffer{packet}))
		require.Equal(t, 1, stream.calls)
		if unsupported {
			require.Greater(t, stream.Len(), minimumLinkMTU)
		} else {
			require.Zero(t, stream.Len())
		}
	}
}
