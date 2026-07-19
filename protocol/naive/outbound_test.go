//go:build with_naive_outbound

package naive

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/stretchr/testify/require"
)

func TestOutboundRejectsCertificateServerName(t *testing.T) {
	_, err := NewOutbound(context.Background(), nil, log.NewNOPFactory().Logger(), "", option.NaiveOutboundOptions{
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
			TLS: &option.OutboundTLSOptions{
				Enabled:               true,
				CertificateServerName: "certificate.example",
			},
		},
	})
	require.ErrorContains(t, err, "certificate_server_name is not supported on naive outbound")
}
