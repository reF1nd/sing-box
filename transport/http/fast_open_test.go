package http

import (
	std_bufio "bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	stdHTTP "net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/debug"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
)

func serveHTTP1UpgradeCapsuleEcho(conn net.Conn, mode string, requestArrived chan<- struct{}, done <-chan struct{}) {
	defer conn.Close()
	reader := std_bufio.NewReader(conn)
	_, err := stdHTTP.ReadRequest(reader)
	if err != nil {
		return
	}
	if requestArrived != nil {
		select {
		case requestArrived <- struct{}{}:
		default:
		}
	}
	switch mode {
	case "silent":
		<-done
		return
	case "reject":
		_, _ = io.WriteString(conn, "HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n")
		return
	case "echo":
		_, err = io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: connect-udp\r\nCapsule-Protocol: ?1\r\n\r\n")
		if err != nil {
			return
		}
		_, _ = io.Copy(conn, reader)
	}
}

func TestHTTP1FastOpenHandshakeTimeout(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })

	serverDone := make(chan struct{})
	t.Cleanup(func() { close(serverDone) })
	requestArrived := make(chan struct{}, 2)
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go serveHTTP1UpgradeCapsuleEcho(conn, "silent", requestArrived, serverDone)
		}
	}()

	client, err := NewClient(ClientOptions{
		Server:      M.SocksaddrFromNet(listener.Addr()),
		Version:     1,
		UDPFastOpen: true,
	})
	require.NoError(t, err)
	t.Cleanup(func() { client.Close() })
	client.handshakeTimeout = 100 * time.Millisecond

	destination := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1).To4(), Port: 53}
	for _, delayedRead := range []bool{false, true} {
		name := "immediate_read"
		if delayedRead {
			name = "delayed_read"
		}
		t.Run(name, func(t *testing.T) {
			packetConn, dialErr := client.ListenPacket(t.Context(), M.SocksaddrFromNet(destination))
			require.NoError(t, dialErr)
			defer packetConn.Close()

			_, writeErr := packetConn.WriteTo([]byte("early"), destination)
			require.NoError(t, writeErr)

			select {
			case <-requestArrived:
			case <-time.After(2 * time.Second):
				t.Fatal("timed out waiting for HTTP/1 upgrade request")
			}

			if delayedRead {
				time.Sleep(180 * time.Millisecond)
			}

			_, _, readErr := packetConn.ReadFrom(make([]byte, 64))
			require.ErrorIs(t, readErr, context.DeadlineExceeded)
			require.NoError(t, packetConn.Close())
		})
	}
}

func TestHTTP1FastOpenDelayedReadAndSurvivesPastHandshakeTimeout(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })

	serverDone := make(chan struct{})
	t.Cleanup(func() { close(serverDone) })
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go serveHTTP1UpgradeCapsuleEcho(conn, "echo", nil, serverDone)
		}
	}()

	client, err := NewClient(ClientOptions{
		Server:      M.SocksaddrFromNet(listener.Addr()),
		Version:     1,
		UDPFastOpen: true,
	})
	require.NoError(t, err)
	t.Cleanup(func() { client.Close() })
	client.handshakeTimeout = 80 * time.Millisecond

	destination := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1).To4(), Port: 53}
	packetConn, err := client.ListenPacket(t.Context(), M.SocksaddrFromNet(destination))
	require.NoError(t, err)
	defer packetConn.Close()

	_, err = packetConn.WriteTo([]byte("early"), destination)
	require.NoError(t, err)

	// Delay the first Read well past handshakeTimeout; background response
	// validation must already have disarmed the handshake timer.
	time.Sleep(180 * time.Millisecond)

	buf := make([]byte, 64)
	packetConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := packetConn.ReadFrom(buf)
	require.NoError(t, err)
	require.Equal(t, "early", string(buf[:n]))

	// Subsequent traffic after handshakeTimeout must still succeed.
	_, err = packetConn.WriteTo([]byte("after-timeout"), destination)
	require.NoError(t, err)
	packetConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err = packetConn.ReadFrom(buf)
	require.NoError(t, err)
	require.Equal(t, "after-timeout", string(buf[:n]))
}

func TestHTTP1FastOpenSetDeadlineDoesNotAbortBackgroundHandshake(t *testing.T) {
	for _, readBeforeExtend := range []bool{false, true} {
		name := "expire_before_first_read"
		if readBeforeExtend {
			name = "read_timeout_then_extend"
		}
		t.Run(name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			t.Cleanup(func() { listener.Close() })

			go func() {
				conn, acceptErr := listener.Accept()
				if acceptErr != nil {
					return
				}
				defer conn.Close()
				reader := std_bufio.NewReader(conn)
				if _, reqErr := stdHTTP.ReadRequest(reader); reqErr != nil {
					return
				}
				// Delay 101 past the caller's short SetDeadline, but well inside handshakeTimeout.
				time.Sleep(120 * time.Millisecond)
				if _, writeErr := io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: connect-udp\r\nCapsule-Protocol: ?1\r\n\r\n"); writeErr != nil {
					return
				}
				_, _ = io.Copy(conn, reader)
			}()

			client, err := NewClient(ClientOptions{
				Server:      M.SocksaddrFromNet(listener.Addr()),
				Version:     1,
				UDPFastOpen: true,
			})
			require.NoError(t, err)
			t.Cleanup(func() { client.Close() })
			client.handshakeTimeout = 2 * time.Second

			destination := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1).To4(), Port: 53}
			packetConn, err := client.ListenPacket(t.Context(), M.SocksaddrFromNet(destination).Unwrap())
			require.NoError(t, err)
			defer packetConn.Close()

			// Before setting any read deadline, deadlinePacketConn preserves the inner ReaderReplaceable contract.
			if readerWithUpstream, ok := packetConn.(N.ReaderWithUpstream); ok {
				require.Equal(t, !debug.Enabled, readerWithUpstream.ReaderReplaceable())
			}

			_, err = packetConn.WriteTo([]byte("early"), destination)
			require.NoError(t, err)

			// Set a short combined SetDeadline that expires before 101 arrives.
			require.NoError(t, packetConn.SetDeadline(time.Now().Add(30*time.Millisecond)))
			if readBeforeExtend {
				_, _, readErr := packetConn.ReadFrom(make([]byte, 64))
				require.ErrorIs(t, readErr, os.ErrDeadlineExceeded)
			} else {
				time.Sleep(60 * time.Millisecond)
			}

			// Extend deadline; background handshake must still complete and deliver traffic.
			require.NoError(t, packetConn.SetDeadline(time.Now().Add(2*time.Second)))
			buf := make([]byte, 64)
			n, _, err := packetConn.ReadFrom(buf)
			require.NoError(t, err)
			require.Equal(t, "early", string(buf[:n]))

			_, err = packetConn.WriteTo([]byte("after-extend"), destination)
			require.NoError(t, err)
			n, _, err = packetConn.ReadFrom(buf)
			require.NoError(t, err)
			require.Equal(t, "after-extend", string(buf[:n]))
		})
	}
}

func TestHTTP1FastOpenRejectionAndConcurrentClose(t *testing.T) {
	t.Run("rejected", func(t *testing.T) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		t.Cleanup(func() { listener.Close() })

		serverDone := make(chan struct{})
		t.Cleanup(func() { close(serverDone) })
		go func() {
			for {
				conn, acceptErr := listener.Accept()
				if acceptErr != nil {
					return
				}
				go serveHTTP1UpgradeCapsuleEcho(conn, "reject", nil, serverDone)
			}
		}()

		client, err := NewClient(ClientOptions{
			Server:      M.SocksaddrFromNet(listener.Addr()),
			Version:     1,
			UDPFastOpen: true,
		})
		require.NoError(t, err)
		t.Cleanup(func() { client.Close() })
		client.handshakeTimeout = 2 * time.Second

		destination := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1).To4(), Port: 53}
		packetConn, err := client.ListenPacket(t.Context(), M.SocksaddrFromNet(destination))
		require.NoError(t, err)
		defer packetConn.Close()

		_, _ = packetConn.WriteTo([]byte("early"), destination)
		_, _, readErr := packetConn.ReadFrom(make([]byte, 64))
		require.Error(t, readErr)
		require.False(t, E.IsTimeout(readErr))
		require.ErrorContains(t, readErr, "authentication required")
	})

	t.Run("concurrent_close", func(t *testing.T) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		t.Cleanup(func() { listener.Close() })

		serverDone := make(chan struct{})
		t.Cleanup(func() { close(serverDone) })
		go func() {
			for {
				conn, acceptErr := listener.Accept()
				if acceptErr != nil {
					return
				}
				go serveHTTP1UpgradeCapsuleEcho(conn, "silent", nil, serverDone)
			}
		}()

		client, err := NewClient(ClientOptions{
			Server:      M.SocksaddrFromNet(listener.Addr()),
			Version:     1,
			UDPFastOpen: true,
		})
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
	})
}

func newTestTLSConfig(t *testing.T, nextProtos []string) *tls.Config {
	t.Helper()
	certificateServer := httptest.NewTLSServer(nil)
	tlsConfig := certificateServer.TLS.Clone()
	certificateServer.Close()
	tlsConfig.NextProtos = nextProtos
	return tlsConfig
}

func newTestHTTP2FastOpenClient(t *testing.T, address M.Socksaddr, handshakeTimeout time.Duration) *Client {
	t.Helper()
	client, err := NewClientWithTLS(t.Context(), log.NewNOPFactory().Logger(), N.SystemDialer,
		option.ServerOptions{Server: address.AddrString(), ServerPort: address.Port},
		option.OutboundTLSOptions{Enabled: true, Insecure: true}, nil,
		ClientOptions{
			Version:                2,
			DisableVersionFallback: true,
			UDPFastOpen:            true,
		})
	require.NoError(t, err)
	t.Cleanup(func() { client.Close() })
	client.handshakeTimeout = handshakeTimeout
	return client
}

func http2SessionStreamCount(client *Client) int {
	client.http2Access.Lock()
	defer client.http2Access.Unlock()
	total := 0
	for _, session := range client.http2Sessions {
		total += session.streams
	}
	return total
}

func TestHTTP2FastOpenSilentPeerBeforeSettingsTimesOut(t *testing.T) {
	if !extendedConnectAvailable {
		t.Skip("HTTP/2 extended CONNECT is unavailable in this build")
	}
	tlsConfig := newTestTLSConfig(t, []string{http2.NextProtoTLS})
	listener, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })

	serverDone := make(chan struct{})
	t.Cleanup(func() { close(serverDone) })
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				defer conn.Close()
				tlsConn := conn.(*tls.Conn)
				if tlsConn.HandshakeContext(t.Context()) != nil {
					return
				}
				// Read client preface but never send HTTP/2 SETTINGS.
				_, _ = io.ReadFull(conn, make([]byte, len(http2.ClientPreface)))
				<-serverDone
			}()
		}
	}()

	client := newTestHTTP2FastOpenClient(t, M.SocksaddrFromNet(listener.Addr()), 120*time.Millisecond)
	destination := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1).To4(), Port: 53}
	started := time.Now()
	_, err = client.ListenPacket(t.Context(), M.SocksaddrFromNet(destination))
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Less(t, time.Since(started), 2*time.Second)
	require.Equal(t, 0, http2SessionStreamCount(client))
}

func TestHTTP2FastOpenSilentPeerTimesOutAndIsolatesOtherStreams(t *testing.T) {
	if !extendedConnectAvailable {
		t.Skip("HTTP/2 extended CONNECT is unavailable in this build")
	}
	tlsConfig := newTestTLSConfig(t, []string{http2.NextProtoTLS})
	listener, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })

	silentArrived := make(chan struct{}, 2)
	h2Server := &http2.Server{}
	handler := stdHTTP.HandlerFunc(func(writer stdHTTP.ResponseWriter, request *stdHTTP.Request) {
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
		flusher := writer.(stdHTTP.Flusher)
		flusher.Flush()
		buffer := make([]byte, 4096)
		for {
			n, readErr := request.Body.Read(buffer)
			if n > 0 {
				if _, writeErr := writer.Write(buffer[:n]); writeErr != nil {
					return
				}
				flusher.Flush()
			}
			if readErr != nil {
				return
			}
		}
	})
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				defer conn.Close()
				tlsConn := conn.(*tls.Conn)
				if tlsConn.HandshakeContext(t.Context()) != nil {
					return
				}
				h2Server.ServeConn(tlsConn, &http2.ServeConnOpts{
					Context: t.Context(),
					Handler: handler,
				})
			}()
		}
	}()

	client := newTestHTTP2FastOpenClient(t, M.SocksaddrFromNet(listener.Addr()), 120*time.Millisecond)
	healthyDest := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1).To4(), Port: 54}
	silentDest := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1).To4(), Port: 53}

	healthyConn, err := client.ListenPacket(t.Context(), M.SocksaddrFromNet(healthyDest))
	require.NoError(t, err)
	defer healthyConn.Close()
	_, err = healthyConn.WriteTo([]byte("early-ok"), healthyDest)
	require.NoError(t, err)

	silentConn, err := client.ListenPacket(t.Context(), M.SocksaddrFromNet(silentDest))
	require.NoError(t, err)
	_, err = silentConn.WriteTo([]byte("early-silent"), silentDest)
	require.NoError(t, err)

	select {
	case <-silentArrived:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for silent HTTP/2 CONNECT request")
	}

	// Wait past handshakeTimeout before first Read on both streams:
	// the silent stream must time out, while the healthy stream must stay open.
	time.Sleep(220 * time.Millisecond)

	_, _, silentErr := silentConn.ReadFrom(make([]byte, 64))
	require.ErrorIs(t, silentErr, context.DeadlineExceeded)
	require.NoError(t, silentConn.Close())
	require.NoError(t, silentConn.Close())

	// Only the healthy stream must remain accounted on the shared HTTP/2 session.
	require.Equal(t, 1, http2SessionStreamCount(client))

	buf := make([]byte, 64)
	healthyConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := healthyConn.ReadFrom(buf)
	require.NoError(t, err)
	require.Equal(t, "early-ok", string(buf[:n]))

	_, err = healthyConn.WriteTo([]byte("still-alive"), healthyDest)
	require.NoError(t, err)
	healthyConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err = healthyConn.ReadFrom(buf)
	require.NoError(t, err)
	require.Equal(t, "still-alive", string(buf[:n]))

	require.NoError(t, healthyConn.Close())
	require.Equal(t, 0, http2SessionStreamCount(client))
}

func TestHTTP2FastOpenConcurrentCloseReleasesOnce(t *testing.T) {
	if !extendedConnectAvailable {
		t.Skip("HTTP/2 extended CONNECT is unavailable in this build")
	}
	tlsConfig := newTestTLSConfig(t, []string{http2.NextProtoTLS})
	listener, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })

	h2Server := &http2.Server{}
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				defer conn.Close()
				tlsConn := conn.(*tls.Conn)
				if tlsConn.HandshakeContext(t.Context()) != nil {
					return
				}
				h2Server.ServeConn(tlsConn, &http2.ServeConnOpts{
					Context: t.Context(),
					Handler: stdHTTP.HandlerFunc(func(writer stdHTTP.ResponseWriter, request *stdHTTP.Request) {
						<-request.Context().Done()
					}),
				})
			}()
		}
	}()

	client := newTestHTTP2FastOpenClient(t, M.SocksaddrFromNet(listener.Addr()), 5*time.Second)
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
	require.Equal(t, 0, http2SessionStreamCount(client))
}
