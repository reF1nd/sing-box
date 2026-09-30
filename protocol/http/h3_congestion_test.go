package http

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/option"
	transportHTTP "github.com/sagernet/sing-box/transport/http"

	"github.com/stretchr/testify/require"
)

func TestH3CongestionConstructorValidation(t *testing.T) {
	for _, algorithm := range []option.H3CongestionControl{"none", "invalid"} {
		_, err := NewInbound(context.Background(), nil, nil, "", option.HTTPInboundOptions{Version: []int{3}, H3CongestionControl: algorithm})
		require.ErrorContains(t, err, "h3_congestion_control")
		_, err = NewOutbound(context.Background(), nil, nil, "", option.HTTPOutboundOptions{Version: 3, H3CongestionControl: algorithm})
		require.ErrorContains(t, err, "h3_congestion_control")
	}
	_, err := NewInbound(context.Background(), nil, nil, "", option.HTTPInboundOptions{H3CongestionControl: option.H3CongestionBBR})
	require.ErrorContains(t, err, "version 3")
	_, err = NewOutbound(context.Background(), nil, nil, "", option.HTTPOutboundOptions{H3CongestionControl: option.H3CongestionBBR})
	require.ErrorContains(t, err, "version 3")
	if transportHTTP.NewHTTP3Client == nil {
		_, err = NewOutbound(context.Background(), nil, nil, "", option.HTTPOutboundOptions{Version: 3, H3CongestionControl: option.H3CongestionBBR})
		require.ErrorContains(t, err, "QUIC support")
		_, err = NewInbound(context.Background(), nil, nil, "", option.HTTPInboundOptions{Version: []int{3}, H3CongestionControl: option.H3CongestionBBR})
		require.ErrorContains(t, err, "QUIC support")
	}
}
