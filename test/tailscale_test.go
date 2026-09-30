//go:build with_tailscale

package main

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/tailscale"

	"github.com/stretchr/testify/require"
)

func TestTailscaleTCPCongestionControl(t *testing.T) {
	for _, algorithm := range []option.TCPCongestionControl{"", "reno", "cubic", "bbr"} {
		t.Run(string(algorithm), func(t *testing.T) {
			ctx, cancel := context.WithCancel(globalCtx)
			defer cancel()
			instance, err := box.New(box.Options{
				Context: ctx,
				Options: option.Options{
					Log: &option.LogOptions{Disabled: true},
					Endpoints: []option.Endpoint{{
						Type: C.TypeTailscale,
						Tag:  "tailscale",
						Options: &option.TailscaleEndpointOptions{
							StateDirectory:       t.TempDir(),
							ControlURL:           "http://127.0.0.1:1",
							TCPCongestionControl: algorithm,
						},
					}},
				},
			})
			require.NoError(t, err)
			defer instance.Close()
			endpoint, loaded := instance.Endpoint().Get("tailscale")
			require.True(t, loaded)
			server := endpoint.(*tailscale.Endpoint).Server()
			require.Equal(t, string(algorithm), server.NetstackTCPCongestionControl)
			// Starting tsnet creates the netstack, which rejects any algorithm sing-tun does not accept.
			require.NoError(t, server.Start())
			require.NoError(t, server.Close())
		})
	}
}
