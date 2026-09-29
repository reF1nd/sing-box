package masque

import (
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
