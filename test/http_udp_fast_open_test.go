//go:build with_quic

package main

import (
	std_bufio "bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	sHTTP "github.com/sagernet/sing-box/transport/http"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
)

func TestHTTPOutboundUDPFastOpen(t *testing.T) {
	for _, version := range []int{1, 2, 3} {
		t.Run("HTTP"+strconv.Itoa(version), func(t *testing.T) {
			_, certPem, keyPem := createSelfSignedCertificate(t, "example.org")
			startTLSHTTPInbound(t, certPem, keyPem, []int{1, 2, 3}, nil)
			startInstance(t, option.Options{
				Inbounds: []option.Inbound{
					{
						Type: C.TypeMixed,
						Options: &option.HTTPMixedInboundOptions{
							ListenOptions: option.ListenOptions{
								Listen:     common.Ptr(badoption.Addr(netip.IPv4Unspecified())),
								ListenPort: clientPort,
							},
						},
					},
				},
				Outbounds: []option.Outbound{
					{
						Type: C.TypeHTTP,
						Options: &option.HTTPOutboundOptions{
							ServerOptions: option.ServerOptions{
								Server:     "127.0.0.1",
								ServerPort: serverPort,
							},
							Username:               "sekai",
							Password:               "password",
							Version:                version,
							DisableVersionFallback: true,
							UDPFastOpen:            true,
							OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
								TLS: &option.OutboundTLSOptions{
									Enabled:         true,
									ServerName:      "example.org",
									CertificatePath: certPem,
								},
							},
						},
					},
				},
			})
			dialer := socks.NewClient(N.SystemDialer, M.ParseSocksaddrHostPort("127.0.0.1", clientPort), socks.Version5, "", "")
			dialUDP := func() (net.PacketConn, error) {
				return dialer.ListenPacket(context.Background(), M.ParseSocksaddrHostPort("127.0.0.1", testPort))
			}
			require.NoError(t, testPingPongWithPacketConn(t, testPort, dialUDP))
			require.NoError(t, testLargeDataWithPacketConn(t, testPort, dialUDP))
		})
	}
}

func newFastOpenTLSClient(t *testing.T, certPem string, port uint16, version int, password string) *sHTTP.Client {
	client, err := sHTTP.NewClientWithTLS(t.Context(), log.NewNOPFactory().Logger(), N.SystemDialer,
		option.ServerOptions{Server: "127.0.0.1", ServerPort: port},
		option.OutboundTLSOptions{Enabled: true, ServerName: "example.org", CertificatePath: certPem},
		sHTTP.ClientOptions{
			Username:    "sekai",
			Password:    password,
			Version:     version,
			UDPFastOpen: true,
		})
	require.NoError(t, err)
	t.Cleanup(func() {
		client.Close()
	})
	return client
}

func TestHTTPOutboundUDPFastOpenRejected(t *testing.T) {
	for _, version := range []int{1, 2, 3} {
		t.Run("HTTP"+strconv.Itoa(version), func(t *testing.T) {
			_, certPem, keyPem := createSelfSignedCertificate(t, "example.org")
			startTLSHTTPInbound(t, certPem, keyPem, []int{1, 2, 3}, nil)
			echo := startUDPEcho(t)
			client := newFastOpenTLSClient(t, certPem, serverPort, version, "wrong")
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			// The rejection is only visible after the tunnel was returned.
			packetConn, err := client.ListenPacket(ctx, M.SocksaddrFromNet(echo))
			require.NoError(t, err)
			defer packetConn.Close()
			packetConn.WriteTo([]byte("ping"), echo)
			packetConn.SetReadDeadline(time.Now().Add(5 * time.Second))
			_, _, err = packetConn.ReadFrom(make([]byte, 64))
			require.Error(t, err)
			require.False(t, E.IsTimeout(err))
			require.ErrorContains(t, err, "authentication required")
		})
	}
}

// serveConnectUDPEcho answers a connect-udp upgrade and echoes the capsules back.
// With waitData set, it reads the first capsule (assumed shorter than 64 bytes)
// before sending the response.
func serveConnectUDPEcho(conn net.Conn, waitData bool) {
	defer conn.Close()
	reader := std_bufio.NewReader(conn)
	_, err := http.ReadRequest(reader)
	if err != nil {
		return
	}
	var early []byte
	if waitData {
		header, err := reader.Peek(2)
		if err != nil {
			return
		}
		early = make([]byte, 2+int(header[1]))
		_, err = io.ReadFull(reader, early)
		if err != nil {
			return
		}
	}
	_, err = conn.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: connect-udp\r\nCapsule-Protocol: ?1\r\n\r\n"))
	if err != nil {
		return
	}
	_, err = conn.Write(early)
	if err != nil {
		return
	}
	io.Copy(conn, reader)
}

func TestHTTPOutboundUDPFastOpenBeforeResponse(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() {
		listener.Close()
	})
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go serveConnectUDPEcho(conn, true)
		}
	}()
	client, err := sHTTP.NewClient(sHTTP.ClientOptions{
		Server:      M.SocksaddrFromNet(listener.Addr()),
		Version:     1,
		UDPFastOpen: true,
	})
	require.NoError(t, err)
	defer client.Close()
	destination := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(testPort)}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	packetConn, err := client.ListenPacket(ctx, M.SocksaddrFromNet(destination))
	require.NoError(t, err)
	defer packetConn.Close()
	for _, payload := range []string{"early", "ping"} {
		_, err = packetConn.WriteTo([]byte(payload), destination)
		require.NoError(t, err)
		packetConn.SetReadDeadline(time.Now().Add(5 * time.Second))
		buffer := make([]byte, 64)
		n, _, err := packetConn.ReadFrom(buffer)
		require.NoError(t, err)
		require.Equal(t, payload, string(buffer[:n]))
	}
}

func TestHTTPOutboundUDPFastOpenHTTP2Fallback(t *testing.T) {
	_, certPem, keyPem := createSelfSignedCertificate(t, "example.org")
	certificate, err := tls.LoadX509KeyPair(certPem, keyPem)
	require.NoError(t, err)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{certificate},
		NextProtos:   []string{http2.NextProtoTLS, "http/1.1"},
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		listener.Close()
	})
	var http2Connections atomic.Int32
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				tlsConn := conn.(*tls.Conn)
				if tlsConn.HandshakeContext(t.Context()) != nil {
					conn.Close()
					return
				}
				if tlsConn.ConnectionState().NegotiatedProtocol != http2.NextProtoTLS {
					serveConnectUDPEcho(conn, false)
					return
				}
				// An HTTP/2 server without SETTINGS_ENABLE_CONNECT_PROTOCOL.
				http2Connections.Add(1)
				defer conn.Close()
				_, err := io.ReadFull(conn, make([]byte, len(http2.ClientPreface)))
				if err != nil {
					return
				}
				framer := http2.NewFramer(conn, conn)
				err = framer.WriteSettings()
				if err != nil {
					return
				}
				for {
					frame, err := framer.ReadFrame()
					if err != nil {
						return
					}
					settings, isSettings := frame.(*http2.SettingsFrame)
					if isSettings && !settings.IsAck() {
						err = framer.WriteSettingsAck()
						if err != nil {
							return
						}
					}
				}
			}()
		}
	}()
	client := newFastOpenTLSClient(t, certPem, uint16(listener.Addr().(*net.TCPAddr).Port), 2, "password")
	destination := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(testPort)}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	packetConn, err := client.ListenPacket(ctx, M.SocksaddrFromNet(destination))
	require.NoError(t, err)
	defer packetConn.Close()
	_, err = packetConn.WriteTo([]byte("ping"), destination)
	require.NoError(t, err)
	packetConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buffer := make([]byte, 64)
	n, _, err := packetConn.ReadFrom(buffer)
	require.NoError(t, err)
	require.Equal(t, "ping", string(buffer[:n]))
	require.Equal(t, int32(1), http2Connections.Load())
}
