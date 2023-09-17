//go:build with_naive_outbound

package naive

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"

	"github.com/stretchr/testify/require"
)

func TestOutboundRejectsCertificatePinSHA256(t *testing.T) {
	_, err := NewOutbound(context.Background(), nil, log.NewNOPFactory().Logger(), "", option.NaiveOutboundOptions{
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
			TLS: &option.OutboundTLSOptions{
				Enabled:              true,
				CertificatePinSHA256: "0000000000000000000000000000000000000000000000000000000000000000",
			},
		},
	})
	require.ErrorContains(t, err, "certificate_pin_sha256 is not supported on naive outbound")
}
