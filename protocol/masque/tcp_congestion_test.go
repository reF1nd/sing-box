package masque

import (
	"fmt"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

func TestTCPCongestionConstructorValidation(t *testing.T) {
	for _, algorithm := range []option.TCPCongestionControl{"invalid", "none", "new_reno"} {
		options := option.MASQUEEndpointOptions{TCPCongestionControl: algorithm}
		_, err := NewClientEndpoint(t.Context(), nil, nil, "", option.MASQUEClientEndpointOptions{MASQUEEndpointOptions: options})
		require.ErrorContains(t, err, "tcp_congestion_control")
		_, err = NewServerEndpoint(t.Context(), nil, nil, "", option.MASQUEServerEndpointOptions{MASQUEEndpointOptions: options})
		require.ErrorContains(t, err, "tcp_congestion_control")
	}
}

func TestTCPCongestionDeviceOptions(t *testing.T) {
	for _, system := range []bool{false, true} {
		for _, algorithm := range []option.TCPCongestionControl{"", "reno", "cubic", "bbr"} {
			t.Run(fmt.Sprintf("system=%v/%s", system, algorithm), func(t *testing.T) {
				ctx := service.ContextWith[adapter.NetworkManager](t.Context(), gsoTestNetworkManager{})
				options := newDeviceOptions(ctx, log.NewNOPFactory().Logger(), nil, option.MASQUEEndpointOptions{
					System:               system,
					TCPCongestionControl: algorithm,
				}, 0, nil)
				require.Equal(t, string(algorithm), options.TCPCongestionControl)
				require.Equal(t, system, options.System)
			})
		}
	}
}
