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
	"net/url"
	"strings"
	"sync"
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
				option.OutboundTLSOptions{Enabled: true, Insecure: mode != "certificate"}, nil,
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

func TestHTTP3FastOpenCapsuleRejectionDuringWrite(t *testing.T) {
	certificateServer := httptest.NewTLSServer(nil)
	tlsConfig := certificateServer.TLS.Clone()
	certificateServer.Close()
	tlsConfig.NextProtos = []string{http3.NextProtoH3}

	socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { socket.Close() })
	listener, err := quic.ListenEarly(socket, tlsConfig, &quic.Config{EnableDatagrams: false})
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })

	allowReject := make(chan struct{})
	var allowRejectOnce sync.Once
	closeAllowReject := func() {
		allowRejectOnce.Do(func() {
			close(allowReject)
		})
	}
	requestArrived := make(chan struct{}, 1)
	server := &http3.Server{
		EnableDatagrams: false,
		Handler: stdHTTP.HandlerFunc(func(writer stdHTTP.ResponseWriter, request *stdHTTP.Request) {
			select {
			case requestArrived <- struct{}{}:
			default:
			}
			select {
			case <-allowReject:
			case <-request.Context().Done():
				return
			}
			writer.WriteHeader(stdHTTP.StatusProxyAuthRequired)
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
	t.Cleanup(closeAllowReject)

	address := M.SocksaddrFromNet(socket.LocalAddr())
	client, err := NewClientWithTLS(t.Context(), log.NewNOPFactory().Logger(), N.SystemDialer,
		option.ServerOptions{Server: address.AddrString(), ServerPort: address.Port},
		option.OutboundTLSOptions{Enabled: true, Insecure: true}, nil,
		ClientOptions{Version: 3, DisableVersionFallback: true, UDPFastOpen: true})
	require.NoError(t, err)
	t.Cleanup(func() { client.Close() })

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	stream, err := client.http3.OpenTunnel(ctx, tunnelRequest{
		protocol:    connectUDPProtocol,
		url:         &url.URL{Path: "/.well-known/masque/udp/127.0.0.1/53/"},
		destination: M.ParseSocksaddr("127.0.0.1:53"),
		fastOpen:    true,
	})
	require.NoError(t, err)
	h3Stream := stream.(*http3RequestDatagramStream)
	require.False(t, h3Stream.datagramsEnabled, "server disabled datagrams so traffic must use capsule stream Write")

	h3Impl := client.http3.(*http3ClientImpl)
	h3Impl.access.Lock()
	conn := h3Impl.conn
	initialStreams := -1
	if conn != nil {
		initialStreams = conn.streams
	}
	h3Impl.access.Unlock()
	require.NotNil(t, conn)
	require.Equal(t, 1, initialStreams)

	// Continuously write capsule bytes while the server rejects asynchronously.
	// Large payloads exercise flow-control blocking in stream.Write concurrently
	// with readResponse's rejection cleanup.
	writeDone := make(chan error, 1)
	writing := make(chan struct{}, 1)
	go func() {
		chunk := make([]byte, 32*1024)
		for i := 0; i < 64; i++ {
			if i == 1 {
				select {
				case writing <- struct{}{}:
				default:
				}
			}
			if _, writeErr := stream.Write(chunk); writeErr != nil {
				writeDone <- writeErr
				return
			}
		}
		writeDone <- nil
	}()

	select {
	case <-requestArrived:
	case <-ctx.Done():
		t.Fatal("timed out waiting for H3 CONNECT request")
	}
	select {
	case <-writing:
	case <-time.After(100 * time.Millisecond):
	}
	closeAllowReject()

	select {
	case writeErr := <-writeDone:
		require.Error(t, writeErr)
	case <-ctx.Done():
		t.Fatal("in-flight capsule Write hung after async H3 rejection")
	}

	_, readErr := stream.Read(make([]byte, 16))
	require.Error(t, readErr)
	require.ErrorContains(t, readErr, "authentication required")

	// Repeated Close calls must be idempotent and release conn.streams exactly once.
	_ = stream.Close()
	_ = stream.Close()
	h3Impl.access.Lock()
	finalStreams := conn.streams
	h3Impl.access.Unlock()
	require.Equal(t, 0, finalStreams)
}

func TestHTTP3FastOpenHandshakeTimeoutAndStreamIsolation(t *testing.T) {
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

	silentArrived := make(chan struct{}, 2)
	server := &http3.Server{
		EnableDatagrams: true,
		Handler: stdHTTP.HandlerFunc(func(writer stdHTTP.ResponseWriter, request *stdHTTP.Request) {
			if strings.HasSuffix(request.URL.Path, "/53/") {
				select {
				case silentArrived <- struct{}{}:
				default:
				}
				<-request.Context().Done()
				return
			}
			writer.Header().Set("Capsule-Protocol", "?1")
			writer.WriteHeader(stdHTTP.StatusOK)
			writer.(stdHTTP.Flusher).Flush()
			stream := writer.(http3.HTTPStreamer).HTTPStream()
			for {
				datagram, recvErr := stream.ReceiveDatagram(request.Context())
				if recvErr != nil {
					return
				}
				if sendErr := stream.SendDatagram(datagram); sendErr != nil {
					return
				}
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
		option.OutboundTLSOptions{Enabled: true, Insecure: true}, nil,
		ClientOptions{Version: 3, UDPFastOpen: true})
	require.NoError(t, err)
	t.Cleanup(func() { client.Close() })
	client.handshakeTimeout = 120 * time.Millisecond

	// Keep fallback enabled with a probe dialer to verify already fast-opened
	// tunnels never replay early UDP packets onto TCP fallback.
	tcpFallback := &fallbackTestDialer{}
	client.tlsDialer = nil
	client.http1Dialer = tcpFallback

	healthyDest := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1).To4(), Port: 54}
	silentDest := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1).To4(), Port: 53}

	healthyConn, err := client.ListenPacket(t.Context(), M.SocksaddrFromNet(healthyDest))
	require.NoError(t, err)
	defer healthyConn.Close()
	_, err = healthyConn.WriteTo([]byte("early-h3"), healthyDest)
	require.NoError(t, err)

	silentConn, err := client.ListenPacket(t.Context(), M.SocksaddrFromNet(silentDest))
	require.NoError(t, err)
	_, err = silentConn.WriteTo([]byte("early-silent"), silentDest)
	require.NoError(t, err)

	select {
	case <-silentArrived:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for silent H3 CONNECT request")
	}

	// Wait past handshakeTimeout before first Read on both streams:
	// the silent stream must time out, while the healthy stream must stay open.
	time.Sleep(220 * time.Millisecond)

	_, _, silentErr := silentConn.ReadFrom(make([]byte, 64))
	require.ErrorIs(t, silentErr, context.DeadlineExceeded)
	require.NoError(t, silentConn.Close())
	require.NoError(t, silentConn.Close())
	require.Zero(t, tcpFallback.calls)

	h3Impl := client.http3.(*http3ClientImpl)
	h3Impl.access.Lock()
	conn := h3Impl.conn
	activeStreams := -1
	if conn != nil {
		activeStreams = conn.streams
	}
	h3Impl.access.Unlock()
	require.NotNil(t, conn)
	require.Equal(t, 1, activeStreams)

	buf := make([]byte, 64)
	healthyConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := healthyConn.ReadFrom(buf)
	require.NoError(t, err)
	require.Equal(t, "early-h3", string(buf[:n]))

	_, err = healthyConn.WriteTo([]byte("after-h3-timeout"), healthyDest)
	require.NoError(t, err)
	healthyConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err = healthyConn.ReadFrom(buf)
	require.NoError(t, err)
	require.Equal(t, "after-h3-timeout", string(buf[:n]))

	require.NoError(t, healthyConn.Close())
	h3Impl.access.Lock()
	finalStreams := conn.streams
	h3Impl.access.Unlock()
	require.Equal(t, 0, finalStreams)
}

func TestHTTP3FastOpenConcurrentCloseReleasesOnce(t *testing.T) {
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

	server := &http3.Server{
		EnableDatagrams: true,
		Handler: stdHTTP.HandlerFunc(func(writer stdHTTP.ResponseWriter, request *stdHTTP.Request) {
			<-request.Context().Done()
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
		option.OutboundTLSOptions{Enabled: true, Insecure: true}, nil,
		ClientOptions{Version: 3, DisableVersionFallback: true, UDPFastOpen: true})
	require.NoError(t, err)
	t.Cleanup(func() { client.Close() })
	client.handshakeTimeout = 5 * time.Second

	destination := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1).To4(), Port: 53}
	packetConn, err := client.ListenPacket(t.Context(), M.SocksaddrFromNet(destination))
	require.NoError(t, err)

	var waitGroup sync.WaitGroup
	waitGroup.Add(2)
	go func() {
		defer waitGroup.Done()
		for range 16 {
			if _, writeErr := packetConn.WriteTo([]byte("burst"), destination); writeErr != nil {
				return
			}
		}
	}()
	go func() {
		defer waitGroup.Done()
		_, _, _ = packetConn.ReadFrom(make([]byte, 64))
	}()

	time.Sleep(20 * time.Millisecond)
	require.NoError(t, packetConn.Close())
	require.NoError(t, packetConn.Close())
	waitGroup.Wait()

	h3Impl := client.http3.(*http3ClientImpl)
	h3Impl.access.Lock()
	finalStreams := h3Impl.conn.streams
	h3Impl.access.Unlock()
	require.Equal(t, 0, finalStreams)
}
