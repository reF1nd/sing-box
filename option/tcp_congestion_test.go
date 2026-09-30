package option

import (
	"fmt"
	"testing"

	"github.com/sagernet/sing/common/json"

	"github.com/stretchr/testify/require"
)

func TestMASQUETCPCongestionJSON(t *testing.T) {
	for _, server := range []bool{false, true} {
		for _, version := range []string{"", `,"version":1`, `,"version":2`, `,"version":3`} {
			for _, value := range []string{`"reno"`, `"cubic"`, `"bbr"`, `""`, `null`, `false`, `3`, `{}`, `[]`, `"none"`, `"new_reno"`, `"brutal"`, `"BBR"`, `"auto"`} {
				t.Run(fmt.Sprintf("server=%v/%s/%s", server, version, value), func(t *testing.T) {
					var options any = new(MASQUEClientEndpointOptions)
					if server {
						options = new(MASQUEServerEndpointOptions)
					}
					err := json.UnmarshalContext(t.Context(), []byte(`{"tcp_congestion_control":`+value+version+`}`), options)
					if value != `"reno"` && value != `"cubic"` && value != `"bbr"` {
						require.ErrorContains(t, err, "tcp_congestion_control")
						return
					}
					require.NoError(t, err)
					encoded, err := json.Marshal(options)
					require.NoError(t, err)
					require.Contains(t, string(encoded), `"tcp_congestion_control":`+value)
					require.NoError(t, json.UnmarshalContext(t.Context(), encoded, options))
				})
			}
		}
	}
	for _, options := range []any{new(MASQUEClientEndpointOptions), new(MASQUEServerEndpointOptions)} {
		require.NoError(t, json.UnmarshalContext(t.Context(), []byte(`{}`), options))
		encoded, err := json.Marshal(options)
		require.NoError(t, err)
		require.NotContains(t, string(encoded), "tcp_congestion_control")
		require.NoError(t, json.UnmarshalContext(t.Context(), []byte(`{"tcp_congestion_control":"bbr","h3_congestion_control":"none"}`), options))
	}
	for _, options := range []any{new(HTTPInboundOptions), new(HTTPOutboundOptions), new(TunInboundOptions)} {
		require.Error(t, json.UnmarshalContextDisallowUnknownFields(t.Context(), []byte(`{"tcp_congestion_control":"bbr"}`), options))
	}
}
