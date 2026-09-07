package v2raygrpclite

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"

	"golang.org/x/net/http2"
)

type failureReader struct{ err error }

func (r failureReader) Read([]byte) (int, error) { return 0, r.err }

type injectedConn struct {
	net.Conn
	failed atomic.Bool
	err    error
}

func (c *injectedConn) Read(p []byte) (int, error) {
	if c.failed.Load() {
		return 0, c.err
	}
	return c.Conn.Read(p)
}

func tlsOverGun(t *testing.T, readErr error) net.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	t.Cleanup(cancel)
	certificateServer := httptest.NewTLSServer(nil)
	certificate := certificateServer.TLS.Certificates[0]
	clientConfig := certificateServer.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	clientConfig.ServerName = "127.0.0.1"
	certificateServer.Close()
	clientRaw, serverRaw := net.Pipe()
	injected := &injectedConn{Conn: clientRaw, err: readErr}
	clientGun := newGunConn(injected, injected, nil)
	serverGun := newGunConn(serverRaw, serverRaw, nil)
	client := tls.Client(clientGun, clientConfig)
	server := tls.Server(serverGun, &tls.Config{Certificates: []tls.Certificate{certificate}})
	serverReady := make(chan error, 1)
	serverDone := make(chan struct{})
	t.Cleanup(func() {
		clientRaw.Close()
		serverRaw.Close()
		<-serverDone
	})
	go func() {
		defer close(serverDone)
		err := server.HandshakeContext(ctx)
		serverReady <- err
		if err == nil {
			io.Copy(io.Discard, server)
		}
	}()
	if err := client.HandshakeContext(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-serverReady; err != nil {
		t.Fatal(err)
	}
	injected.failed.Store(true)
	return client
}

type boundedConn struct {
	net.Conn
	reads   atomic.Int64
	onClose func()
}

func (c *boundedConn) Read(p []byte) (int, error) {
	if c.reads.Add(1) > 16 {
		return 0, io.EOF
	}
	return c.Conn.Read(p)
}

func (c *boundedConn) Close() error {
	err := c.Conn.Close()
	c.onClose()
	return err
}

func checkReadLoopExit(t *testing.T, conn net.Conn) {
	t.Helper()
	closed := make(chan struct{})
	bounded := &boundedConn{Conn: conn, onClose: sync.OnceFunc(func() { close(closed) })}
	transport := &http2.Transport{}
	cc, err := transport.NewClientConn(bounded)
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("HTTP/2 read loop did not close the failed connection")
	}
	if reads := bounded.reads.Load(); reads != 1 {
		t.Fatalf("HTTP/2 retried a terminal transport error: %d reads", reads)
	}
}

func TestGunConnNestedHTTP2StreamError(t *testing.T) {
	original := http2.StreamError{StreamID: 169, Code: http2.ErrCodeProtocol}
	t.Run("plain", func(t *testing.T) {
		checkReadLoopExit(t, newGunConn(failureReader{original}, io.Discard, nil))
	})
	t.Run("tls", func(t *testing.T) {
		checkReadLoopExit(t, tlsOverGun(t, original))
	})
}

type failureWriter struct{ err error }

func (w failureWriter) Write([]byte) (int, error) { return 0, w.err }

func TestGunConnStreamError(t *testing.T) {
	for _, code := range []http2.ErrCode{http2.ErrCodeProtocol, http2.ErrCodeInternal} {
		t.Run(code.String(), func(t *testing.T) {
			original := http2.StreamError{StreamID: 169, Code: code, Cause: errors.New("peer reset")}
			conn := newGunConn(failureReader{original}, failureWriter{original}, nil)
			late := newLateGunConn(io.Discard)
			late.setup(nil, original)
			operations := map[string]func() error{
				"read":  func() error { _, err := conn.Read(make([]byte, 1)); return err },
				"setup": func() error { _, err := late.Read(make([]byte, 1)); return err },
				"write": func() error { _, err := conn.Write([]byte("payload")); return err },
				"write_buffer": func() error {
					buffer := buf.NewSize(conn.FrontHeadroom() + 7)
					buffer.Resize(conn.FrontHeadroom(), 0)
					buffer.WriteString("payload")
					return conn.WriteBuffer(buffer)
				},
			}
			for name, operation := range operations {
				t.Run(name, func(t *testing.T) {
					err := operation()
					if _, naked := err.(http2.StreamError); naked {
						t.Fatal("transport leaked a bare HTTP/2 stream error")
					}
					var streamError http2.StreamError
					if !errors.Is(err, original) || !errors.As(err, &streamError) || streamError != original {
						t.Fatalf("lost original stream error: %v", err)
					}
				})
			}
		})
	}
}

// An actual RST_STREAM must terminate the nested connection without closing
// unrelated streams on the same underlying HTTP/2 connection.
func TestGunConnResetStreamIsolation(t *testing.T) {
	reset := make(chan struct{})
	releaseHealthy := make(chan struct{})
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		if r.URL.Path == "/reset" {
			select {
			case <-reset:
				panic(http.ErrAbortHandler) // net/http sends RST_STREAM(INTERNAL_ERROR).
			case <-r.Context().Done():
				return
			}
		}
		select {
		case <-releaseHealthy:
			conn := newGunConn(r.Body, w, w.(http.Flusher))
			conn.Write([]byte("healthy"))
		case <-r.Context().Done():
		}
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	config := server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	config.NextProtos = []string{http2.NextProtoTLS}
	dialer := &tls.Dialer{Config: config}
	raw, err := dialer.DialContext(ctx, "tcp", server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	transport := &http2.Transport{}
	cc, err := transport.NewClientConn(raw)
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()
	open := func(path string) io.ReadCloser {
		t.Helper()
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, server.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		response, err := cc.RoundTrip(request)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { response.Body.Close() })
		return response.Body
	}
	resetBody := open("/reset")
	healthyBody := open("/healthy")
	close(reset)
	checkReadLoopExit(t, newGunConn(resetBody, io.Discard, nil))
	close(releaseHealthy)
	healthy := newGunConn(healthyBody, io.Discard, nil)
	payload := make([]byte, len("healthy"))
	if _, err := io.ReadFull(healthy, payload); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(payload, []byte("healthy")) {
		t.Fatalf("unexpected healthy stream payload: %q", payload)
	}
	fresh := newGunConn(open("/fresh"), io.Discard, nil)
	if _, err := io.ReadFull(fresh, payload); err != nil {
		t.Fatalf("underlying HTTP/2 connection no longer reusable: %v", err)
	}
}
