package parser

import (
	"testing"

	"github.com/sagernet/sing-box/option"

	"github.com/stretchr/testify/require"
)

func TestHysteriaBuildQUICOptions(t *testing.T) {
	options := (&HysteriaOption{
		ReceiveWindowConn:   65536,
		ReceiveWindow:       32768,
		DisableMTUDiscovery: true,
	}).Build().(*option.HysteriaOutboundOptions)
	require.Equal(t, uint64(65536), options.ConnectionReceiveWindow.Value())
	require.Equal(t, uint64(32768), options.StreamReceiveWindow.Value())
	require.True(t, options.DisablePathMTUDiscovery)
}
