//go:build with_quic

package http

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	stdHTTP "net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

func TestHTTP3TransportErrorClassification(t *testing.T) {
	for _, testCase := range []struct {
		name     string
		err      error
		fallback bool
	}{
		{"handshake_timeout", &quic.HandshakeTimeoutError{}, true},
		{"idle_timeout", &quic.IdleTimeoutError{}, true},
		{"connection_reset", &quic.StatelessResetError{}, true},
		{"connect_eof", io.EOF, true},
		{"no_h3_alpn", &quic.TransportError{ErrorCode: 0x178}, true},
		{"bad_certificate", &quic.TransportError{ErrorCode: 0x12a}, false},
		{"certificate_verification", &tls.CertificateVerificationError{Err: errors.New("untrusted")}, false},
		{"canceled", context.Canceled, false},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			err := wrapHTTP3Error(testCase.err)
			require.Equal(t, testCase.fallback, errors.Is(err, ErrHTTP3Unavailable))
			require.ErrorIs(t, err, testCase.err)
		})
	}
}

func TestHTTP3DatagramSessionErrorClassification(t *testing.T) {
	stream := &http3RequestDatagramStream{}
	streamError := &quic.StreamError{ErrorCode: 0, Remote: false}
	require.NotErrorIs(t, stream.wrapError(streamError), ErrHTTP3Unavailable)
	require.ErrorIs(t, stream.wrapError(&quic.IdleTimeoutError{}), ErrHTTP3Unavailable)
	require.ErrorIs(t, stream.wrapError(&quic.ApplicationError{Remote: true}), ErrHTTP3Unavailable)
	require.NotErrorIs(t, stream.wrapError(context.Canceled), ErrHTTP3Unavailable)
	require.NotErrorIs(t, stream.wrapError(&quic.ApplicationError{Remote: false}), ErrHTTP3Unavailable)
	stream.closed.Store(true)
	require.NotErrorIs(t, stream.wrapError(io.ErrUnexpectedEOF), ErrHTTP3Unavailable)
}

func TestHTTP3TunnelFailureFallback(t *testing.T) {
	for _, testCase := range []struct {
		mode      string
		algorithm option.H3CongestionControl
	}{
		{"before_response", ""},
		{"established", ""},
		{"authentication", ""},
		{"certificate", ""},
		{"before_response", "none"},
		{"established", "none"},
		{"authentication", "none"},
		{"certificate", "none"},
	} {
		t.Run(testCase.mode+"/"+string(testCase.algorithm), func(t *testing.T) {
			mode := testCase.mode
			certificateServer := httptest.NewTLSServer(nil)
			tlsConfig := certificateServer.TLS.Clone()
			certificateServer.Close()
			tlsConfig.NextProtos = []string{http3.NextProtoH3}
			socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
			require.NoError(t, err)
			t.Cleanup(func() { socket.Close() })
			listener, err := quic.ListenEarly(socket, tlsConfig, &quic.Config{EnableDatagrams: true})
			require.NoError(t, err)
			t.Cleanup(func() { listener.Close() })
			type connectionKey struct{}
			connections := make(chan *quic.Conn, 1)
			server := &http3.Server{
				EnableDatagrams: true,
				ConnContext: func(ctx context.Context, conn *quic.Conn) context.Context {
					return context.WithValue(ctx, connectionKey{}, conn)
				},
				Handler: stdHTTP.HandlerFunc(func(writer stdHTTP.ResponseWriter, request *stdHTTP.Request) {
					conn := request.Context().Value(connectionKey{}).(*quic.Conn)
					switch mode {
					case "before_response":
						conn.CloseWithError(0x102, "test connection failure")
					case "authentication":
						writer.WriteHeader(stdHTTP.StatusUnauthorized)
					default:
						writer.WriteHeader(stdHTTP.StatusOK)
						writer.(stdHTTP.Flusher).Flush()
						connections <- conn
						<-request.Context().Done()
					}
				}),
			}
			serverDone := make(chan struct{})
			go func() {
				defer close(serverDone)
				server.ServeListener(listener)
			}()
			t.Cleanup(func() {
				server.Close()
				<-serverDone
			})
			address := M.SocksaddrFromNet(socket.LocalAddr())
			client, err := NewClientWithTLS(t.Context(), log.NewNOPFactory().Logger(), N.SystemDialer,
				option.ServerOptions{Server: address.AddrString(), ServerPort: address.Port},
				option.OutboundTLSOptions{Enabled: true, Insecure: mode != "certificate"},
				ClientOptions{Version: 3, H3CongestionControl: testCase.algorithm})
			require.NoError(t, err)
			t.Cleanup(func() { client.Close() })
			tcp := &fallbackTestDialer{}
			client.tlsDialer = nil
			client.http1Dialer = tcp
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			stream, err := client.OpenTunnel(ctx, "connect-ip", "/")
			if mode == "authentication" || mode == "certificate" {
				require.Error(t, err)
				require.NotErrorIs(t, err, ErrHTTP3Unavailable)
				require.Zero(t, tcp.calls)
				return
			}
			require.NoError(t, err)
			defer stream.Close()
			if mode == "established" {
				require.Zero(t, tcp.calls)
				var conn *quic.Conn
				select {
				case conn = <-connections:
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
				require.NoError(t, conn.CloseWithError(0x102, "test connection failure"))
				// MASQUE continuously reads capsules as well as datagrams. Reading
				// the closed stream also notifies its HTTP/3 datagram receiver.
				_, err = stream.Read(make([]byte, 1))
				require.ErrorIs(t, err, ErrHTTP3Unavailable)
				_, err = stream.(DatagramStream).ReceiveDatagram(ctx)
				require.ErrorIs(t, err, ErrHTTP3Unavailable)
				client.ReportTunnelError(err)
				nextStream, err := client.OpenTunnel(ctx, "connect-ip", "/")
				require.NoError(t, err)
				nextStream.Close()
			}
			require.Equal(t, 1, tcp.calls)
		})
	}
}
