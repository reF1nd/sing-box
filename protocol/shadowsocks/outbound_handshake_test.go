package shadowsocks

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-shadowsocks2"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

func TestShadowsocks2022ConcurrentFirstPayload(t *testing.T) {
	for _, method := range []string{"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"} {
		for _, buffered := range []bool{false, true} {
			name := method + "/write"
			if buffered {
				name += "-buffer"
			}
			t.Run(name, func(t *testing.T) {
				password := handshakeTestPassword(method)
				client, server := net.Pipe()
				t.Cleanup(func() { client.Close(); server.Close() })
				require.NoError(t, client.SetDeadline(time.Now().Add(5*time.Second)))
				require.NoError(t, server.SetDeadline(time.Now().Add(5*time.Second)))
				routed := make(chan adapter.InboundContext, 1)
				router := &handshakeTestRouter{routed: routed}
				inbound, err := NewInbound(context.Background(), router, log.NewNOPFactory().NewLogger("test"), "in", option.ShadowsocksInboundOptions{Method: method, Password: password})
				require.NoError(t, err)
				t.Cleanup(func() { inbound.Close() })
				finished := make(chan struct{})
				go func() {
					defer close(finished)
					defer server.Close()
					inbound.(adapter.TCPInjectableInbound).NewConnection(context.Background(), server, adapter.InboundContext{}, nil)
				}()
				dialer := newHandshakeTestDialer(t, method, client)
				target := M.ParseSocksaddr("target.example:443")
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				conn, err := dialer.DialContext(ctx, N.NetworkTCP, target)
				require.NoError(t, err)
				// Cancelling a completed dial must not close the returned connection.
				cancel()
				// A large first payload forces simultaneous reads and writes even
				// when the transport cannot buffer a complete request.
				payload := bytes.Repeat([]byte("concurrent first payload"), 8192)
				writeDone := make(chan error, 1)
				go func() {
					var writeErr error
					if buffered {
						writeErr = conn.(N.ExtendedWriter).WriteBuffer(buf.As(append([]byte(nil), payload...)))
					} else {
						_, writeErr = conn.Write(payload)
					}
					writeDone <- writeErr
				}()
				reply := make([]byte, len(payload))
				_, err = io.ReadFull(conn, reply)
				require.NoError(t, err)
				require.NoError(t, <-writeDone)
				require.Equal(t, payload, reply)
				require.Equal(t, target, (<-routed).Destination)
				conn.Close()
				select {
				case <-finished:
				case <-time.After(5 * time.Second):
					t.Fatal("inbound did not finish")
				}
			})
		}
	}
}

func TestShadowsocks2022HandshakeFailure(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	defer client.Close()
	writeErr := errors.New("handshake write failed")
	transport := &handshakeTestConn{Conn: client, writeErr: writeErr}
	dialer := newHandshakeTestDialer(t, "2022-blake3-aes-128-gcm", transport)
	conn, err := dialer.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr("target.example:443"))
	require.ErrorIs(t, err, writeErr)
	require.Nil(t, conn)
	_, err = server.Read(make([]byte, 1))
	require.ErrorIs(t, err, io.EOF)
}

func TestShadowsocks2022HandshakeCancellation(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	defer client.Close()
	started := make(chan struct{})
	transport := &handshakeTestConn{Conn: client, started: started}
	dialer := newHandshakeTestDialer(t, "2022-blake3-aes-128-gcm", transport)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, err := dialer.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr("target.example:443"))
		result <- err
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("handshake did not start")
	}
	cancel()
	select {
	case err := <-result:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(5 * time.Second):
		t.Fatal("handshake did not stop after cancellation")
	}
	_, err := server.Read(make([]byte, 1))
	require.ErrorIs(t, err, io.EOF)
}

func TestShadowsocksLegacyKeepsEarlyHandshake(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	defer client.Close()
	transport := &handshakeTestConn{Conn: client, writeErr: errors.New("unexpected eager write")}
	dialer := newHandshakeTestDialer(t, "aes-128-gcm", transport)
	conn, err := dialer.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr("target.example:443"))
	require.NoError(t, err)
	conn.Close()
}

func handshakeTestPassword(method string) string {
	length := 32
	if method == "2022-blake3-aes-128-gcm" {
		length = 16
	}
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, length))
}

func newHandshakeTestDialer(t *testing.T, methodName string, conn net.Conn) *shadowsocksDialer {
	t.Helper()
	method, err := shadowsocks.CreateMethod(context.Background(), methodName, shadowsocks.MethodOptions{Password: handshakeTestPassword(methodName)})
	require.NoError(t, err)
	return &shadowsocksDialer{logger: log.NewNOPFactory().NewLogger("test"), method: method, dialer: &handshakeTestDialer{conn: conn}}
}

type handshakeTestDialer struct {
	N.Dialer
	conn net.Conn
}

func (d *handshakeTestDialer) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return d.conn, nil
}

type handshakeTestConn struct {
	net.Conn
	writeErr error
	started  chan struct{}
	once     sync.Once
}

func (c *handshakeTestConn) Write(p []byte) (int, error) {
	if c.started != nil {
		c.once.Do(func() { close(c.started) })
	}
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	return c.Conn.Write(p)
}

type handshakeTestRouter struct {
	adapter.Router
	routed chan adapter.InboundContext
}

//nolint:staticcheck
func (r *handshakeTestRouter) RouteConnection(_ context.Context, conn net.Conn, metadata adapter.InboundContext) error {
	defer conn.Close()
	r.routed <- metadata
	_, err := io.Copy(conn, conn)
	return err
}
