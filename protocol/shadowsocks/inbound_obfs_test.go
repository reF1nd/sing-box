package shadowsocks

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

func TestInboundSimpleObfs(t *testing.T) {
	serverKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 16))
	userKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 16))
	for _, kind := range []string{"single-aead", "single-2022", "multi-aead", "multi-2022", "managed", "relay"} {
		for _, mode := range []string{"", "http", "tls"} {
			t.Run(kind+"/"+mode, func(t *testing.T) {
				ctx := context.Background()
				logger := log.NewNOPFactory().NewLogger("test")
				options := option.ShadowsocksInboundOptions{
					ListenOptions: option.ListenOptions{Listen: common.Ptr(badoption.Addr(netip.MustParseAddr("127.0.0.1")))},
					Network:       N.NetworkTCP,
					Method:        "2022-blake3-aes-128-gcm",
					Password:      serverKey,
					ObfsMode:      mode,
					// The server accepts the client's camouflage host independently.
					ObfsHost: "server.example",
				}
				clientPassword := serverKey
				expectedUser := ""
				switch kind {
				case "single-aead":
					options.Method = "aes-128-gcm"
				case "multi-aead":
					options.Method = "aes-128-gcm"
					options.Users = []option.ShadowsocksUser{{Name: "alice", Password: userKey}}
					clientPassword = userKey
					expectedUser = "alice"
				case "multi-2022":
					options.Users = []option.ShadowsocksUser{{Name: "alice", Password: userKey}}
					clientPassword = serverKey + ":" + userKey
					expectedUser = "alice"
				case "managed":
					options.Managed = true
					clientPassword = serverKey + ":" + userKey
					expectedUser = "alice"
				case "relay":
					options.Destinations = []option.ShadowsocksDestination{{Name: "backend", Password: userKey, ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: 12345}}}
					clientPassword = serverKey + ":" + userKey
				}
				routed := make(chan adapter.InboundContext, 1)
				finished := make(chan struct{})
				echoRouter := &obfsTestRouter{route: func(_ context.Context, conn net.Conn, metadata adapter.InboundContext) error {
					defer close(finished)
					defer conn.Close()
					routed <- metadata
					_, err := io.Copy(conn, conn)
					return err
				}}
				var router adapter.Router = echoRouter
				relayRouted := make(chan adapter.InboundContext, 1)
				if kind == "relay" {
					backend, err := NewInbound(ctx, echoRouter, logger, "backend", option.ShadowsocksInboundOptions{Method: options.Method, Password: userKey})
					require.NoError(t, err)
					t.Cleanup(func() { require.NoError(t, backend.Close()) })
					router = &obfsTestRouter{route: func(ctx context.Context, conn net.Conn, metadata adapter.InboundContext) error {
						relayRouted <- metadata
						backend.(adapter.TCPInjectableInbound).NewConnection(ctx, conn, metadata, nil)
						return nil
					}}
				}
				inbound, err := NewInbound(ctx, router, logger, "ss-in", options)
				require.NoError(t, err)
				t.Cleanup(func() { require.NoError(t, inbound.Close()) })
				if kind == "managed" {
					require.NoError(t, inbound.(*MultiInbound).UpdateUsers([]string{"alice"}, []string{userKey}))
				}
				require.NoError(t, inbound.Start(adapter.StartStateStart))
				var address M.Socksaddr
				switch inbound := inbound.(type) {
				case *Inbound:
					address = M.SocksaddrFromNet(inbound.listener.TCPListener().Addr())
				case *MultiInbound:
					address = M.SocksaddrFromNet(inbound.listener.TCPListener().Addr())
				case *RelayInbound:
					address = M.SocksaddrFromNet(inbound.listener.TCPListener().Addr())
				}
				outOptions := option.ShadowsocksOutboundOptions{
					ServerOptions: option.ServerOptions{Server: address.Addr.String(), ServerPort: address.Port},
					Method:        options.Method,
					Password:      clientPassword,
				}
				if mode != "" {
					outOptions.Plugin = "obfs-local"
					outOptions.PluginOptions = "obfs=" + mode + ";obfs-host=client.example"
				}
				outbound, err := NewOutbound(ctx, nil, logger, "ss-out", outOptions)
				require.NoError(t, err)
				t.Cleanup(func() { require.NoError(t, common.Close(outbound)) })
				target := M.ParseSocksaddr("target.example:443")
				conn, err := outbound.DialContext(ctx, N.NetworkTCP, target)
				require.NoError(t, err)
				t.Cleanup(func() { conn.Close() })
				require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
				for _, payload := range [][]byte{[]byte("first request"), bytes.Repeat([]byte("follow-up payload"), 8192)} {
					writeResult := make(chan error, 1)
					go func() {
						_, writeErr := conn.Write(payload)
						writeResult <- writeErr
					}()
					reply := make([]byte, len(payload))
					_, err = io.ReadFull(conn, reply)
					require.NoError(t, err)
					require.NoError(t, <-writeResult)
					require.Equal(t, payload, reply)
				}
				metadata := <-routed
				require.Equal(t, target, metadata.Destination)
				require.Equal(t, expectedUser, metadata.User)
				if kind == "relay" {
					metadata = <-relayRouted
					require.Equal(t, options.Destinations[0].Build(), metadata.Destination)
					require.Equal(t, "backend", metadata.User)
				}
				conn.Close()
				select {
				case <-finished:
				case <-time.After(5 * time.Second):
					t.Fatal("inbound did not finish after client close")
				}
			})
		}
	}
}

func TestInboundRejectsInvalidObfsMode(t *testing.T) {
	for _, options := range []option.ShadowsocksInboundOptions{
		{},
		{Users: []option.ShadowsocksUser{{Password: "user"}}},
		{Managed: true},
		{Destinations: []option.ShadowsocksDestination{{Password: "user"}}},
	} {
		options.ObfsMode = "invalid"
		_, err := NewInbound(context.Background(), nil, log.NewNOPFactory().NewLogger("test"), "ss-in", options)
		require.EqualError(t, err, "shadowsocks: unsupported obfs mode: invalid")
	}
}

type obfsTestRouter struct {
	adapter.Router
	route func(context.Context, net.Conn, adapter.InboundContext) error
}

//nolint:staticcheck
func (r *obfsTestRouter) RouteConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext) error {
	return r.route(ctx, conn, metadata)
}
