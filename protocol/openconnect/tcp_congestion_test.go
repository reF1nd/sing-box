package openconnect

import (
	"testing"

	"github.com/sagernet/sing-box/option"

	"github.com/stretchr/testify/require"
)

func TestTCPCongestionConstructorValidation(t *testing.T) {
	for _, algorithm := range []option.TCPCongestionControl{"invalid", "none", "new_reno"} {
		_, err := NewEndpoint(t.Context(), nil, nil, "", option.OpenConnectEndpointOptions{TCPCongestionControl: algorithm})
		require.ErrorContains(t, err, "tcp_congestion_control")
	}
}
