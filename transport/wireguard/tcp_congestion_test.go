package wireguard

import (
	"encoding/base64"
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"

	"github.com/stretchr/testify/require"
)

func TestEndpointTCPCongestionControl(t *testing.T) {
	outboundDialer, err := dialer.NewDefault(t.Context(), option.DialerOptions{})
	require.NoError(t, err)
	for _, algorithm := range []string{"", "reno", "cubic", "bbr", "invalid"} {
		t.Run(algorithm, func(t *testing.T) {
			endpoint, err := NewEndpoint(EndpointOptions{
				TCPCongestionControl: algorithm,
				Context:              t.Context(),
				Logger:               logger.NOP(),
				Dialer:               outboundDialer,
				PrivateKey:           base64.StdEncoding.EncodeToString(make([]byte, 32)),
				Address:              []netip.Prefix{netip.MustParsePrefix("172.16.0.2/32")},
			})
			require.NoError(t, err)
			err = endpoint.Initialize(nil)
			if algorithm == "invalid" {
				// Rejection by sing-tun proves the option reached the actual TCP stack.
				require.ErrorContains(t, err, "unknown congestion control")
				return
			}
			require.NoError(t, err)
			require.NoError(t, endpoint.Start(false))
			require.NoError(t, endpoint.Close())
		})
	}
}
