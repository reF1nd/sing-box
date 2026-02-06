package masque

import (
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

type gsoTestNetworkManager struct {
	adapter.NetworkManager
}

func (gsoTestNetworkManager) InterfaceFinder() control.InterfaceFinder {
	return nil
}

func TestMASQUEGSOConfiguration(t *testing.T) {
	for _, server := range []bool{false, true} {
		role := "client"
		if server {
			role = "server"
		}
		for _, testCase := range []struct {
			name   string
			config string
			system bool
			gso    bool
		}{
			{"internal_default", `{}`, false, false},
			{"system_default", `{"system":true}`, true, true},
			{"system_disabled", `{"system":true,"gso":false}`, true, false},
			{"system_enabled", `{"system":true,"gso":true}`, true, true},
			{"internal_explicit", `{"system":false,"gso":true}`, false, true},
		} {
			t.Run(role+"/"+testCase.name, func(t *testing.T) {
				ctx := service.ContextWith[adapter.NetworkManager](t.Context(), gsoTestNetworkManager{})
				var deviceOptions option.MASQUEEndpointOptions
				var encoded []byte
				var err error
				if server {
					var options option.MASQUEServerEndpointOptions
					require.NoError(t, json.UnmarshalContext(ctx, []byte(testCase.config), &options))
					deviceOptions = options.MASQUEEndpointOptions
					encoded, err = json.Marshal(options)
				} else {
					var options option.MASQUEClientEndpointOptions
					require.NoError(t, json.UnmarshalContext(ctx, []byte(testCase.config), &options))
					deviceOptions = options.MASQUEEndpointOptions
					encoded, err = json.Marshal(options)
				}
				require.NoError(t, err)
				var input, output map[string]json.RawMessage
				require.NoError(t, json.Unmarshal([]byte(testCase.config), &input))
				require.NoError(t, json.Unmarshal(encoded, &output))
				require.Equal(t, input["gso"], output["gso"], "preserve omitted and explicit false values")
				device := newDeviceOptions(ctx, log.NewNOPFactory().Logger(), nil, deviceOptions, 0, nil)
				require.Equal(t, testCase.system, device.System, "GSO must not enable a system interface")
				require.Equal(t, testCase.gso, device.GSO)
			})
		}
	}
}
