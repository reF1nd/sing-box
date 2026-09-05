package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"testing"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks"

	"github.com/stretchr/testify/require"
)

func anyTLSListenOptions(t *testing.T) option.ListenOptions {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	port := M.SocksaddrFromNet(listener.Addr()).Port
	require.NoError(t, listener.Close())
	return option.ListenOptions{Listen: common.Ptr(badoption.Addr(netip.MustParseAddr("127.0.0.1"))), ListenPort: port}
}

func TestAnyTLSSelf(t *testing.T) {
	ca, cert, key := createSelfSignedCertificate(t, "anytls.test")
	for _, fastOpen := range []bool{false, true} {
		for _, disableReuse := range []bool{false, true} {
			t.Run(fmt.Sprintf("tfo=%t/disable_reuse=%t", fastOpen, disableReuse), func(t *testing.T) {
				inListen, proxyListen := anyTLSListenOptions(t), anyTLSListenOptions(t)
				startInstance(t, option.Options{
					Inbounds: []option.Inbound{
						{Type: C.TypeMixed, Tag: "mixed", Options: &option.HTTPMixedInboundOptions{ListenOptions: proxyListen}},
						{Type: C.TypeAnyTLS, Tag: "anytls", Options: &option.AnyTLSInboundOptions{
							ListenOptions:              inListen,
							Users:                      []option.AnyTLSUser{{Name: "test", Password: "password"}},
							InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{TLS: &option.InboundTLSOptions{Enabled: true, CertificatePath: cert, KeyPath: key}},
						}},
					},
					Outbounds: []option.Outbound{
						{Type: C.TypeDirect, Tag: "direct"},
						{Type: C.TypeAnyTLS, Tag: "anytls-out", Options: &option.AnyTLSOutboundOptions{
							DialerOptions:               option.DialerOptions{AbstractDialerOptions: option.AbstractDialerOptions{TCPFastOpen: fastOpen}},
							ServerOptions:               option.ServerOptions{Server: "127.0.0.1", ServerPort: inListen.ListenPort},
							OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: &option.OutboundTLSOptions{Enabled: true, ServerName: "anytls.test", CertificatePath: ca}},
							Password:                    "password", DisableReuse: disableReuse,
						}},
					},
					Route: &option.RouteOptions{Rules: []option.Rule{{Type: C.RuleTypeDefault, DefaultOptions: option.DefaultRule{
						RawDefaultRule: option.RawDefaultRule{Inbound: []string{"mixed"}},
						RuleAction:     option.RuleAction{Action: C.RuleActionTypeRoute, RouteOptions: option.RouteActionOptions{Outbound: "anytls-out"}},
					}}}},
				})
				dialer := socks.NewClient(N.SystemDialer, M.ParseSocksaddrHostPort("127.0.0.1", proxyListen.ListenPort), socks.Version5, "", "")
				// Cover TCP and UoT with both short and multi-frame payloads.
				for _, size := range []int{16, 128 * 1024} {
					echo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						body, err := io.ReadAll(r.Body)
						if err != nil {
							http.Error(w, err.Error(), http.StatusBadRequest)
							return
						}
						w.Write(body)
					}))
					t.Cleanup(echo.Close)
					client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
						return dialer.DialContext(ctx, network, M.ParseSocksaddr(address))
					}}}
					payload := bytes.Repeat([]byte("x"), size)
					t.Cleanup(client.CloseIdleConnections)
					response, err := client.Post(echo.URL, "application/octet-stream", bytes.NewReader(payload))
					require.NoError(t, err)
					body, err := io.ReadAll(response.Body)
					require.NoError(t, err)
					require.Len(t, body, len(payload))
					require.True(t, bytes.Equal(payload, body), "payload differs")
					response.Body.Close()
					client.CloseIdleConnections()
					echo.Close()
				}
				udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
				require.NoError(t, err)
				defer udp.Close()
				done := make(chan error, 1)
				go func() {
					buffer := make([]byte, 2048)
					n, address, err := udp.ReadFrom(buffer)
					if err == nil {
						_, err = udp.WriteTo(buffer[:n], address)
					}
					done <- err
				}()
				conn, err := dialer.ListenPacket(context.Background(), M.SocksaddrFromNet(udp.LocalAddr()))
				require.NoError(t, err)
				defer conn.Close()
				require.NoError(t, conn.SetDeadline(time.Now().Add(10*time.Second)))
				_, err = conn.WriteTo([]byte("uot"), udp.LocalAddr())
				require.NoError(t, err)
				buffer := make([]byte, 16)
				n, _, err := conn.ReadFrom(buffer)
				require.NoError(t, err)
				require.Equal(t, "uot", string(buffer[:n]))
				require.NoError(t, <-done)
			})
		}
	}
}

func TestAnyTLSFallback(t *testing.T) {
	ca, cert, key := createSelfSignedCertificate(t, "anytls.test")
	caBytes, err := os.ReadFile(ca)
	require.NoError(t, err)
	roots := x509.NewCertPool()
	require.True(t, roots.AppendCertsFromPEM(caBytes))
	defaultServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "default:"+r.URL.Path) }))
	defer defaultServer.Close()
	alpnServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "alpn:"+r.URL.Path) }))
	defer alpnServer.Close()
	toOptions := func(address net.Addr) *option.ServerOptions {
		addr := M.SocksaddrFromNet(address)
		return &option.ServerOptions{Server: addr.Addr.String(), ServerPort: addr.Port}
	}
	for _, testCase := range []struct {
		name, alpn, expected          string
		withTLS, withDefault, withMap bool
	}{
		{name: "plain", withDefault: true, expected: "default:/test"},
		{name: "tls-default", withTLS: true, withDefault: true, expected: "default:/test"},
		{name: "alpn-match", withTLS: true, withDefault: true, withMap: true, alpn: "http/1.1", expected: "alpn:/test"},
		{name: "alpn-only", withTLS: true, withMap: true, alpn: "http/1.1", expected: "alpn:/test"},
		{name: "alpn-reject", withTLS: true, withDefault: true, withMap: true, alpn: "h2"},
		{name: "no-alpn-default", withTLS: true, withDefault: true, withMap: true, expected: "default:/test"},
		{name: "no-alpn-reject", withTLS: true, withMap: true},
		{name: "disabled"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			options := &option.AnyTLSInboundOptions{ListenOptions: anyTLSListenOptions(t), Users: []option.AnyTLSUser{{Name: "test", Password: "password"}}}
			if testCase.withTLS {
				options.TLS = &option.InboundTLSOptions{Enabled: true, CertificatePath: cert, KeyPath: key, ALPN: []string{"h2", "http/1.1"}}
			}
			if testCase.withDefault {
				options.Fallback = toOptions(defaultServer.Listener.Addr())
			}
			if testCase.withMap {
				options.FallbackForALPN = map[string]*option.ServerOptions{"http/1.1": toOptions(alpnServer.Listener.Addr())}
			}
			startInstance(t, option.Options{Inbounds: []option.Inbound{{Type: C.TypeAnyTLS, Tag: "anytls", Options: options}}, Outbounds: []option.Outbound{{Type: C.TypeDirect, Tag: "direct"}}})
			address := M.ParseSocksaddrHostPort("127.0.0.1", options.ListenPort).String()
			var conn net.Conn
			if testCase.withTLS {
				config := &tls.Config{RootCAs: roots, ServerName: "anytls.test"}
				if testCase.alpn != "" {
					config.NextProtos = []string{testCase.alpn}
				}
				conn, err = tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", address, config)
			} else {
				conn, err = net.DialTimeout("tcp", address, 5*time.Second)
			}
			require.NoError(t, err)
			defer conn.Close()
			require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
			_, err = io.WriteString(conn, "GET /test HTTP/1.1\r\nHost: anytls.test\r\nConnection: close\r\n\r\n")
			require.NoError(t, err)
			response, readErr := io.ReadAll(conn)
			if testCase.expected == "" {
				require.Empty(t, response)
				if netErr, ok := readErr.(net.Error); ok {
					require.False(t, netErr.Timeout(), "rejected fallback must close promptly")
				}
			} else {
				require.NoError(t, readErr)
				require.Contains(t, string(response), testCase.expected)
			}
		})
	}
}
