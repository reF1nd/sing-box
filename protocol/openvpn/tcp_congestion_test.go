package openvpn

import (
	"testing"

	"github.com/sagernet/sing-box/option"

	"github.com/stretchr/testify/require"
)

func TestTCPCongestionConstructorValidation(t *testing.T) {
	for _, algorithm := range []option.TCPCongestionControl{"invalid", "none", "new_reno"} {
		options := option.OpenVPNEndpointOptions{TCPCongestionControl: algorithm}
		_, err := NewClientEndpoint(t.Context(), nil, nil, "", option.OpenVPNClientEndpointOptions{OpenVPNEndpointOptions: options})
		require.ErrorContains(t, err, "tcp_congestion_control")
		_, err = NewServerEndpoint(t.Context(), nil, nil, "", option.OpenVPNServerEndpointOptions{OpenVPNEndpointOptions: options})
		require.ErrorContains(t, err, "tcp_congestion_control")
	}
}
