package option

import (
	"context"
	"fmt"
	"testing"

	"github.com/sagernet/sing/common/json"

	"github.com/stretchr/testify/require"
)

func TestH3CongestionJSON(t *testing.T) {
	for _, endpoint := range []string{"masque-client", "masque-server", "http-out", "http-in"} {
		for _, version := range []string{"", `,"version":0`, `,"version":1`, `,"version":2`, `,"version":3`, `,"version":[1,2]`, `,"version":[2,3]`, `,"version":[]`} {
			for _, algorithm := range []string{"new_reno", "cubic", "bbr", "none", "", "brutal", "BBR", "auto"} {
				t.Run(endpoint+version+"/"+algorithm, func(t *testing.T) {
					var options any
					server, masque := false, false
					switch endpoint {
					case "masque-client":
						options = new(MASQUEClientEndpointOptions)
						masque = true
					case "masque-server":
						options = new(MASQUEServerEndpointOptions)
						server = true
						masque = true
					case "http-out":
						options = new(HTTPOutboundOptions)
					case "http-in":
						options = new(HTTPInboundOptions)
						server = true
					}
					allowedAlgorithm := algorithm == "new_reno" || algorithm == "cubic" || algorithm == "bbr" || algorithm == "none" && masque
					allowedVersion := version == `,"version":3` || server && version == `,"version":[2,3]` || masque && version == "" || masque && !server && version == `,"version":0` || masque && server && version == `,"version":[]`
					content := []byte(fmt.Sprintf(`{"h3_congestion_control":%q%s}`, algorithm, version))
					err := json.UnmarshalContext(context.Background(), content, options)
					if !allowedAlgorithm || !allowedVersion {
						require.Error(t, err)
						return
					}
					require.NoError(t, err)
					encoded, err := json.Marshal(options)
					require.NoError(t, err)
					require.Contains(t, string(encoded), `"h3_congestion_control":"`+algorithm+`"`)
					require.NoError(t, json.UnmarshalContext(context.Background(), encoded, options))
				})
			}
		}
	}
	for _, value := range []string{`null`, `false`, `3`, `{}`, `[]`} {
		var options MASQUEClientEndpointOptions
		require.Error(t, json.UnmarshalContext(context.Background(), []byte(`{"h3_congestion_control":`+value+`}`), &options))
	}
	for _, options := range []any{new(MASQUEClientEndpointOptions), new(MASQUEServerEndpointOptions), new(HTTPInboundOptions), new(HTTPOutboundOptions)} {
		require.NoError(t, json.UnmarshalContext(context.Background(), []byte(`{}`), options))
		encoded, err := json.Marshal(options)
		require.NoError(t, err)
		require.NotContains(t, string(encoded), "h3_congestion_control")
	}
	var independent HTTPClientOptions
	require.Error(t, json.UnmarshalContext(context.Background(), []byte(`{"version":3,"h3_congestion_control":"bbr"}`), &independent))
}

func TestH3CongestionValidation(t *testing.T) {
	require.NoError(t, H3CongestionControl("").Validate([]int{1}, false))
	require.Error(t, H3CongestionControl("invalid").Validate([]int{3}, true))
	require.Error(t, H3CongestionNone.Validate([]int{3}, false))
	require.Error(t, H3CongestionBBR.Validate([]int{2}, true))
	require.NoError(t, H3CongestionNone.Validate([]int{1, 2, 3}, true))
}
