package parser

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/option"
	"github.com/stretchr/testify/require"
)

func TestParseClashSnellObfsOptions(t *testing.T) {
	outbounds, endpoints, err := ParseClashSubscription(context.Background(), `
proxies:
  - name: snell-out
    type: snell
    server: 127.0.0.1
    port: 1080
    psk: password
    version: 5
    udp: true
    obfs-opts:
      mode: http
      host: example.com
`)
	require.NoError(t, err)
	require.Empty(t, endpoints)
	require.Len(t, outbounds, 1)

	snellOptions, ok := outbounds[0].Options.(*option.SnellOutboundOptions)
	require.True(t, ok)
	require.Equal(t, 4, snellOptions.Version)
	require.Equal(t, option.NetworkList("tcp\nudp"), snellOptions.Network)
	require.Equal(t, "http", snellOptions.ObfsOptions.ObfsMode)
	require.Equal(t, "example.com", snellOptions.ObfsOptions.ObfsHost)
}
