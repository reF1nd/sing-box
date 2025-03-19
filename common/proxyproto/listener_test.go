package proxyproto

import (
	"errors"
	"io"
	"net"
	"os"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	N "github.com/sagernet/sing/common/network"

	"github.com/pires/go-proxyproto"
	"github.com/stretchr/testify/require"
)

type trackingCloseConn struct {
	net.Conn
	closed atomic.Bool
}

func (c *trackingCloseConn) Close() error {
	c.closed.Store(true)
	return c.Conn.Close()
}

type chanListener struct {
	ch chan net.Conn
}

func (l *chanListener) Accept() (net.Conn, error) {
	conn, ok := <-l.ch
	if !ok {
		return nil, net.ErrClosed
	}
	return conn, nil
}

func (l *chanListener) Close() error {
	return nil
}

func (l *chanListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
}

func TestListenerAcceptDoesNotBlockOnStalledClientAndClosesOnTimeout(t *testing.T) {
	rawListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	ppListener := &Listener{
		Listener:    rawListener,
		ReadTimeout: 100 * time.Millisecond,
	}
	defer ppListener.Close()

	// Client 1 connects and stalls without sending any bytes.
	stalledClient, err := net.Dial("tcp", rawListener.Addr().String())
	require.NoError(t, err)
	defer stalledClient.Close()

	// Client 2 connects right behind client 1 and sends a valid v1 header + payload.
	goodClient, err := net.Dial("tcp", rawListener.Addr().String())
	require.NoError(t, err)
	defer goodClient.Close()
	_, err = goodClient.Write([]byte("PROXY TCP4 192.0.2.10 198.51.100.20 54321 443\r\nhello"))
	require.NoError(t, err)

	// Accept must return client 2 immediately without waiting for client 1's timeout.
	type acceptOut struct {
		conn net.Conn
		err  error
	}
	acceptCh := make(chan acceptOut, 1)
	go func() {
		conn, acceptErr := ppListener.Accept()
		acceptCh <- acceptOut{conn: conn, err: acceptErr}
	}()
	var got acceptOut
	select {
	case got = <-acceptCh:
	case <-time.After(time.Second):
		t.Fatal("Accept blocked on stalled client")
	}
	require.NoError(t, got.err)
	defer got.conn.Close()
	require.Equal(t, "192.0.2.10:54321", got.conn.RemoteAddr().String())
	require.Equal(t, "198.51.100.20:443", got.conn.LocalAddr().String())
	payload := make([]byte, 5)
	_, err = io.ReadFull(got.conn, payload)
	require.NoError(t, err)
	require.Equal(t, "hello", string(payload))

	// After the server's ReadTimeout, the stalled client socket must observe
	// peer close (EOF/reset), NOT the client's own read deadline timeout.
	buf := make([]byte, 1)
	_ = stalledClient.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, readErr := stalledClient.Read(buf)
	require.Error(t, readErr, "stalled client socket must be closed by server after header timeout")
	var netErr net.Error
	if errors.As(readErr, &netErr) {
		require.False(t, netErr.Timeout(), "client read timed out instead of observing server close: %v", readErr)
	}
}

func TestListenerMalformedHeaderClosesUnderlyingConnAndNeverSurfaces(t *testing.T) {
	badServer, badClient := net.Pipe()
	defer badClient.Close()
	trackedBad := &trackingCloseConn{Conn: badServer}

	goodServer, goodClient := net.Pipe()
	defer goodClient.Close()

	chListener := &chanListener{ch: make(chan net.Conn, 2)}
	chListener.ch <- trackedBad
	chListener.ch <- goodServer
	close(chListener.ch)

	ppListener := &Listener{
		Listener:    chListener,
		ReadTimeout: time.Second,
	}
	defer ppListener.Close()

	go func() {
		_, _ = badClient.Write([]byte("PROXY INVALID HEADER\r\n"))
	}()
	go func() {
		_, _ = goodClient.Write([]byte("PROXY TCP4 192.0.2.50 198.51.100.60 40000 8443\r\nok"))
	}()

	conn, err := ppListener.Accept()
	require.NoError(t, err)
	defer conn.Close()
	require.Equal(t, "192.0.2.50:40000", conn.RemoteAddr().String())
	got := make([]byte, 2)
	_, err = io.ReadFull(conn, got)
	require.NoError(t, err)
	require.Equal(t, "ok", string(got))

	require.Eventually(t, trackedBad.closed.Load, time.Second, 10*time.Millisecond, "underlying connection must be closed on invalid PROXY header")

	// Next Accept must see the closed underlying listener, never the bad conn.
	_, err = ppListener.Accept()
	require.ErrorIs(t, err, net.ErrClosed)
}

func TestListenerV2AcceptNoHeaderAndSyscallConnUnwrap(t *testing.T) {
	t.Run("v2_and_ktls_unwrap", func(t *testing.T) {
		rawListener, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)

		ppListener := &Listener{Listener: rawListener, ReadTimeout: time.Second}
		defer ppListener.Close()

		client, err := net.Dial("tcp", rawListener.Addr().String())
		require.NoError(t, err)
		defer client.Close()

		header := proxyproto.HeaderProxyFromAddrs(2,
			&net.TCPAddr{IP: net.ParseIP("192.0.2.11"), Port: 11111},
			&net.TCPAddr{IP: net.ParseIP("198.51.100.22"), Port: 8443},
		)
		_, err = header.WriteTo(client)
		require.NoError(t, err)
		_, err = client.Write([]byte("v2data"))
		require.NoError(t, err)

		conn, err := ppListener.Accept()
		require.NoError(t, err)
		defer conn.Close()
		require.Equal(t, "192.0.2.11:11111", conn.RemoteAddr().String())
		require.Equal(t, "198.51.100.22:8443", conn.LocalAddr().String())
		got := make([]byte, 6)
		_, err = io.ReadFull(conn, got)
		require.NoError(t, err)
		require.Equal(t, "v2data", string(got))

		// Once buffered bytes are drained (as after a TLS handshake), callers
		// such as kTLS must be able to unwrap down to the underlying syscall.Conn.
		syscallConn, ok := N.CastReader[interface {
			io.Reader
			syscall.Conn
		}](conn)
		require.True(t, ok, "accepted connection must unwrap to syscall.Conn once cached bytes are drained")
		require.IsType(t, (*net.TCPConn)(nil), syscallConn)
	})

	t.Run("accept_no_header", func(t *testing.T) {
		rawListener, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)

		ppListener := &Listener{Listener: rawListener, AcceptNoHeader: true, ReadTimeout: time.Second}
		defer ppListener.Close()

		client, err := net.Dial("tcp", rawListener.Addr().String())
		require.NoError(t, err)
		defer client.Close()
		_, err = client.Write([]byte("GET / HTTP/1.1\r\n"))
		require.NoError(t, err)

		conn, err := ppListener.Accept()
		require.NoError(t, err)
		defer conn.Close()
		got := make([]byte, len("GET / HTTP/1.1\r\n"))
		_, err = io.ReadFull(conn, got)
		require.NoError(t, err)
		require.Equal(t, "GET / HTTP/1.1\r\n", string(got))

		syscallConn, ok := N.CastReader[interface {
			io.Reader
			syscall.Conn
		}](conn)
		require.True(t, ok)
		require.IsType(t, (*net.TCPConn)(nil), syscallConn)
	})
}

func TestListenerCloseCancelsPendingHeaderReads(t *testing.T) {
	rawListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	ppListener := &Listener{Listener: rawListener, ReadTimeout: 30 * time.Second}
	stalledClient, err := net.Dial("tcp", rawListener.Addr().String())
	require.NoError(t, err)
	defer stalledClient.Close()

	acceptDone := make(chan error, 1)
	go func() {
		_, acceptErr := ppListener.Accept()
		acceptDone <- acceptErr
	}()

	// Wait until the server has accepted the stalled socket into pending.
	require.Eventually(t, func() bool {
		ppListener.mu.Lock()
		n := len(ppListener.pending)
		ppListener.mu.Unlock()
		return n == 1
	}, time.Second, 5*time.Millisecond)

	require.NoError(t, ppListener.Close())
	select {
	case acceptErr := <-acceptDone:
		require.ErrorIs(t, acceptErr, net.ErrClosed)
	case <-time.After(time.Second):
		t.Fatal("Accept did not unblock after Listener.Close")
	}

	buf := make([]byte, 1)
	_ = stalledClient.SetReadDeadline(time.Now().Add(time.Second))
	_, readErr := stalledClient.Read(buf)
	require.Error(t, readErr)
	var netErr net.Error
	if errors.As(readErr, &netErr) {
		require.False(t, netErr.Timeout(), "pending socket was not closed on Listener.Close: %v", readErr)
	}
}

func TestErrorTimeoutPreservesUnderlyingTimeout(t *testing.T) {
	timeoutErr := &Error{os.ErrDeadlineExceeded}
	require.True(t, timeoutErr.Timeout())

	parseErr := &Error{proxyproto.ErrInvalidUpstream}
	require.False(t, parseErr.Timeout())
}

type countingListener struct {
	ch       chan net.Conn
	accepted atomic.Int32
}

func (l *countingListener) Accept() (net.Conn, error) {
	conn, ok := <-l.ch
	if !ok {
		return nil, net.ErrClosed
	}
	l.accepted.Add(1)
	return conn, nil
}

func (l *countingListener) Close() error   { return nil }
func (l *countingListener) Addr() net.Addr { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345} }

func TestListenerBoundsInFlightWhenAcceptPaused(t *testing.T) {
	inner := &countingListener{ch: make(chan net.Conn, 5)}
	ppListener := &Listener{
		Listener:    inner,
		ReadTimeout: time.Second,
		MaxInFlight: 2,
	}

	var clients []net.Conn
	var servers []*trackingCloseConn
	for range 4 {
		s, c := net.Pipe()
		tracked := &trackingCloseConn{Conn: s}
		servers = append(servers, tracked)
		clients = append(clients, c)
		inner.ch <- tracked
	}
	defer func() {
		for _, c := range clients {
			_ = c.Close()
		}
	}()

	// Write valid PROXY headers on all 4 connections concurrently.
	for i, c := range clients {
		go func(idx int, conn net.Conn) {
			_, _ = conn.Write([]byte("PROXY TCP4 192.0.2.1 198.51.100.1 50000 443\r\n"))
		}(i, c)
	}

	// Start acceptLoop via init() without consuming from Accept() (simulating
	// callers like OpenVPN static_key that pause Accept while a peer is active).
	ppListener.init()

	// Exactly MaxInFlight (2) connections may be pulled from inner while Accept is paused.
	require.Eventually(t, func() bool {
		return inner.accepted.Load() == 2
	}, time.Second, 5*time.Millisecond)
	time.Sleep(50 * time.Millisecond)
	require.Equal(t, int32(2), inner.accepted.Load(), "in-flight connections must be capped at MaxInFlight while Accept is paused")

	// Consuming one connection frees one slot so the 3rd connection is accepted.
	conn1, err := ppListener.Accept()
	require.NoError(t, err)
	require.NoError(t, conn1.Close())

	require.Eventually(t, func() bool {
		return inner.accepted.Load() == 3
	}, time.Second, 5*time.Millisecond)
	time.Sleep(50 * time.Millisecond)
	require.Equal(t, int32(3), inner.accepted.Load(), "in-flight connections must remain capped at MaxInFlight")

	// Closing the listener must release and close the remaining in-flight connections.
	require.NoError(t, ppListener.Close())
	require.Eventually(t, func() bool {
		closedCount := 0
		for _, s := range servers[:3] {
			if s.closed.Load() {
				closedCount++
			}
		}
		return closedCount == 3
	}, time.Second, 5*time.Millisecond)
}
