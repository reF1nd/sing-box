package masque

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/option"
	transportHTTP "github.com/sagernet/sing-box/transport/http"

	"github.com/stretchr/testify/require"
)

func TestH3CongestionConstructorValidation(t *testing.T) {
	for _, version := range []int{1, 2} {
		_, err := NewClientEndpoint(context.Background(), nil, nil, "", option.MASQUEClientEndpointOptions{Version: version, H3CongestionControl: option.H3CongestionNone})
		require.ErrorContains(t, err, "version 3")
		_, err = NewServerEndpoint(context.Background(), nil, nil, "", option.MASQUEServerEndpointOptions{Version: []int{version}, H3CongestionControl: option.H3CongestionNone})
		require.ErrorContains(t, err, "version 3")
	}
	_, err := NewClientEndpoint(context.Background(), nil, nil, "", option.MASQUEClientEndpointOptions{H3CongestionControl: "invalid"})
	require.ErrorContains(t, err, "h3_congestion_control")
	_, err = NewServerEndpoint(context.Background(), nil, nil, "", option.MASQUEServerEndpointOptions{H3CongestionControl: "invalid"})
	require.ErrorContains(t, err, "h3_congestion_control")
	if transportHTTP.NewHTTP3Client == nil {
		_, err = NewClientEndpoint(context.Background(), nil, nil, "", option.MASQUEClientEndpointOptions{H3CongestionControl: option.H3CongestionNone})
		require.ErrorContains(t, err, "QUIC support")
		_, err = NewServerEndpoint(context.Background(), nil, nil, "", option.MASQUEServerEndpointOptions{H3CongestionControl: option.H3CongestionNone})
		require.ErrorContains(t, err, "QUIC support")
	}
}
