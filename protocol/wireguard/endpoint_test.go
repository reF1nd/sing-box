//go:build with_wireguard && with_gvisor

package wireguard_test

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/stretchr/testify/require"
)

func TestWireGuardDetourToSelector(t *testing.T) {
	ctx, cancel := context.WithCancel(include.Context(context.Background()))
	defer cancel()
	logPath := filepath.Join(t.TempDir(), "sing-box.log")
	instance, err := box.New(box.Options{
		Context: ctx,
		Options: option.Options{
			Log: &option.LogOptions{
				Level:  "debug",
				Output: logPath,
			},
			Endpoints: []option.Endpoint{
				{
					Type: C.TypeWireGuard,
					Tag:  "wireguard-detour-test",
					Options: &option.WireGuardEndpointOptions{
						Address:    []netip.Prefix{netip.MustParsePrefix("10.255.255.2/32")},
						PrivateKey: "eJRYaHsRX2QaxonVesurCtiXCg5umweoD4czEAX3420=",
						Peers: []option.WireGuardPeer{
							{
								Address:    "127.0.0.1",
								Port:       51820,
								PublicKey:  "9F/usgBr2TvDstYFVJv0doEbZZ5Yrm/XtTau4qnHGTw=",
								AllowedIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
							},
						},
						Workers: 1,
						DialerOptions: option.DialerOptions{
							Detour: "selector",
						},
					},
				},
			},
			Outbounds: []option.Outbound{
				{
					Type: C.TypeSelector,
					Tag:  "selector",
					Options: &option.SelectorOutboundOptions{
						GroupCommonOption: option.GroupCommonOption{
							Outbounds: []string{"direct"},
						},
					},
				},
				{
					Type:    C.TypeDirect,
					Tag:     "direct",
					Options: &option.DirectOutboundOptions{},
				},
			},
		},
	})
	require.NoError(t, err)
	require.NoError(t, instance.Start())
	t.Cleanup(func() {
		require.NoError(t, instance.Close())
	})

	var logs string
	require.Eventually(t, func() bool {
		content, readErr := os.ReadFile(logPath)
		if readErr != nil {
			return false
		}
		logs = string(content)
		return strings.Contains(logs, "outbound detour not found: selector") ||
			strings.Contains(logs, "outbound/direct[direct]: outbound packet connection")
	}, 5*time.Second, 10*time.Millisecond, "WireGuard did not dial through the selected outbound")
	require.NotContains(t, logs, "outbound detour not found: selector")
	require.Contains(t, logs, "outbound/direct[direct]: outbound packet connection")
}
