package vless

import (
	"context"
	"encoding/json"
	"net"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

func TestOutboundTLSDisabled(t *testing.T) {
	for _, test := range []struct {
		name   string
		config string
	}{
		{"omitted", `{}`},
		{"empty", `{"tls":{}}`},
		{"disabled", `{"tls":{"enabled":false}}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, network := range []string{"tcp", "udp", "packet"} {
				t.Run(network, func(t *testing.T) {
					listener, err := net.Listen("tcp", "127.0.0.1:0")
					require.NoError(t, err)
					defer listener.Close()
					options := option.VLESSOutboundOptions{
						ServerOptions: option.ServerOptions{
							Server:     "127.0.0.1",
							ServerPort: uint16(listener.Addr().(*net.TCPAddr).Port),
						},
						UUID: "00000000-0000-4000-8000-000000000001",
					}
					require.NoError(t, json.Unmarshal([]byte(test.config), &options.OutboundTLSOptionsContainer))
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					outbound, err := NewOutbound(ctx, nil, log.NewNOPFactory().Logger(), "test", options)
					require.NoError(t, err)
					destination := M.ParseSocksaddr("127.0.0.1:80")
					require.NotPanics(t, func() {
						if network == "packet" {
							conn, err := outbound.ListenPacket(ctx, destination)
							require.NoError(t, err)
							require.NoError(t, conn.Close())
						} else {
							conn, err := outbound.DialContext(ctx, network, destination)
							require.NoError(t, err)
							require.NoError(t, conn.Close())
						}
					})
				})
			}
		})
	}
}

func TestOutboundTLSEnabled(t *testing.T) {
	server := httptest.NewTLSServer(nil)
	defer server.Close()
	for _, insecure := range []bool{true, false} {
		name := "handshake_success"
		if !insecure {
			name = "certificate_rejected"
		}
		t.Run(name, func(t *testing.T) {
			options := option.VLESSOutboundOptions{
				ServerOptions: option.ServerOptions{
					Server:     "127.0.0.1",
					ServerPort: uint16(server.Listener.Addr().(*net.TCPAddr).Port),
				},
				UUID: "00000000-0000-4000-8000-000000000001",
				OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
					TLS: &option.OutboundTLSOptions{Enabled: true, Insecure: insecure},
				},
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			outbound, err := NewOutbound(ctx, nil, log.NewNOPFactory().Logger(), "test", options)
			require.NoError(t, err)
			conn, err := outbound.DialContext(ctx, "tcp", M.ParseSocksaddr("127.0.0.1:80"))
			if conn != nil {
				defer conn.Close()
			}
			if insecure {
				require.NoError(t, err)
				require.NotNil(t, conn)
			} else {
				require.Error(t, err)
				require.Nil(t, conn)
			}
		})
	}
}
