//go:build with_tailscale

package tailscale

import (
	"testing"

	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/tailscale/tsnet"

	"github.com/stretchr/testify/require"
)

func TestTCPCongestionConstructorValidation(t *testing.T) {
	for _, algorithm := range []option.TCPCongestionControl{"invalid", "none", "new_reno"} {
		_, err := NewEndpoint(t.Context(), nil, nil, "", option.TailscaleEndpointOptions{TCPCongestionControl: algorithm})
		require.ErrorContains(t, err, "tcp_congestion_control")
	}
}

func TestNetstackTCPCongestionControl(t *testing.T) {
	for _, algorithm := range []string{"", "reno", "cubic", "bbr", "invalid"} {
		t.Run(algorithm, func(t *testing.T) {
			outboundDialer, err := dialer.NewDefault(t.Context(), option.DialerOptions{})
			require.NoError(t, err)
			server := &tsnet.Server{
				Dir:                          t.TempDir(),
				ControlURL:                   "http://127.0.0.1:1",
				Dialer:                       outboundDialer,
				NetstackTCPCongestionControl: algorithm,
				Logf:                         func(string, ...any) {},
				UserLogf:                     func(string, ...any) {},
			}
			defer server.Close()
			err = server.Start()
			if algorithm == "invalid" {
				// Rejection by sing-tun proves the option reached the netstack TCP stack.
				require.ErrorContains(t, err, "unknown congestion control")
				return
			}
			require.NoError(t, err)
		})
	}
}
