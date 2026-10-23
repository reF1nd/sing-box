package http

import (
	std_bufio "bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const (
	handshakePending int32 = iota
	handshakeSucceeded
	handshakeFailed
	handshakeTimedOut
	handshakeClosed
)

type tunnelRequest struct {
	protocol            string
	url                 *url.URL
	destination         M.Socksaddr
	originAuthorization bool
	// fastOpen returns the tunnel once the request is sent, before the response
	// arrives. The response is verified asynchronously under handshakeTimeout
	// and checked on the first read.
	fastOpen         bool
	handshakeTimeout time.Duration
}

func (c *Client) OpenTunnel(ctx context.Context, protocol string, path string) (io.ReadWriteCloser, error) {
	requestURL, err := url.ParseRequestURI(path)
	if err != nil {
		return nil, E.Cause(err, "parse tunnel path")
	}
	conn, stream, err := c.openTunnel(ctx, tunnelRequest{
		protocol:            protocol,
		url:                 &url.URL{Path: requestURL.Path, RawPath: requestURL.RawPath, RawQuery: requestURL.RawQuery},
		destination:         c.server,
		originAuthorization: true,
	})
	if err != nil {
		return nil, err
	}
	if stream != nil {
		return stream, nil
	}
	return conn, nil
}

func (c *Client) openTunnel(ctx context.Context, request tunnelRequest) (net.Conn, DatagramStream, error) {
	if request.handshakeTimeout <= 0 {
		request.handshakeTimeout = c.effectiveHandshakeTimeout()
	}
	if c.http3Available() && !c.http3ExtendedConnectUnsupported.Load() {
		attemptCtx, cancel := c.http3AttemptContext(ctx)
		stream, err := c.http3.OpenTunnel(attemptCtx, request)
		err = http3AttemptError(ctx, attemptCtx, err)
		cancel()
		if err == nil {
			c.clearHTTP3Broken()
			return nil, stream, nil
		}
		if c.disableVersionFallback {
			return nil, nil, err
		}
		if errors.Is(err, errHTTP3ExtendedConnectUnsupported) {
			c.http3ExtendedConnectUnsupported.Store(true)
		} else if errors.Is(err, ErrHTTP3Unavailable) {
			c.markHTTP3Broken()
		} else {
			return nil, nil, err
		}
	}
	if !extendedConnectAvailable && c.tlsDialer != nil && c.disableVersionFallback {
		return nil, nil, errExtendedConnectUnavailable
	}
	if extendedConnectAvailable && c.tlsDialer != nil && !c.http2Unsupported.Load() && !c.http2ExtendedConnectUnsupported.Load() {
		session, conn, err := c.acquireHTTP2(ctx)
		if err != nil {
			return nil, nil, err
		}
		if session != nil {
			streamConn, connectErr := c.openTunnelHTTP2(ctx, session, request)
			if connectErr == nil {
				return streamConn, nil, nil
			}
			if !errors.Is(connectErr, errExtendedConnectUnsupported) || c.disableVersionFallback {
				return nil, nil, connectErr
			}
			c.http2ExtendedConnectUnsupported.Store(true)
		} else if c.disableVersionFallback {
			conn.Close()
			return nil, nil, ErrHTTP2Unsupported
		} else {
			return c.openTunnelHTTP1AndClose(ctx, conn, request)
		}
	}
	conn, err := c.http1Dialer.DialContext(ctx, N.NetworkTCP, c.server)
	if err != nil {
		return nil, nil, err
	}
	return c.openTunnelHTTP1AndClose(ctx, conn, request)
}

func (c *Client) openTunnelHTTP1AndClose(ctx context.Context, conn net.Conn, request tunnelRequest) (net.Conn, DatagramStream, error) {
	timeout := request.handshakeTimeout
	if timeout <= 0 {
		timeout = c.effectiveHandshakeTimeout()
	}
	handshakeDeadline := time.Now().Add(timeout)
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	tunnelConn, err := c.openTunnelHTTP1(ctx, conn, request, handshakeDeadline)
	if err != nil {
		conn.Close()
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
		return nil, nil, err
	}
	return tunnelConn, nil, nil
}

func (c *Client) openTunnelHTTP1(ctx context.Context, conn net.Conn, request tunnelRequest, handshakeDeadline time.Time) (net.Conn, error) {
	stop := context.AfterFunc(ctx, func() {
		conn.Close()
	})
	defer stop()
	httpRequest := &http.Request{
		Method: http.MethodGet,
		URL:    request.url,
		Host:   c.authority(),
		Header: buildRequestHeader(c.headers, c.authorization, request.originAuthorization),
	}
	httpRequest.Header.Set("Connection", "Upgrade")
	httpRequest.Header.Set("Upgrade", request.protocol)
	httpRequest.Header.Set("Capsule-Protocol", "?1")
	err := httpRequest.Write(conn)
	if err != nil {
		return nil, E.Cause(err, "write request")
	}
	if request.fastOpen {
		if !stop() {
			return nil, ctx.Err()
		}
		remaining := time.Until(handshakeDeadline)
		if remaining <= 0 {
			return nil, context.DeadlineExceeded
		}
		return newHTTP1EarlyConn(conn, httpRequest, request.protocol, remaining), nil
	}
	reader := std_bufio.NewReader(conn)
	err = readUpgradeResponse(reader, httpRequest, request.protocol)
	if err != nil {
		return nil, err
	}
	if !stop() {
		return nil, ctx.Err()
	}
	if reader.Buffered() > 0 {
		buffer := buf.NewSize(reader.Buffered())
		_, err = buffer.ReadFullFrom(reader, buffer.FreeLen())
		if err != nil {
			buffer.Release()
			return nil, err
		}
		return bufio.NewCachedConn(conn, buffer), nil
	}
	return conn, nil
}

func readUpgradeResponse(reader *std_bufio.Reader, request *http.Request, protocol string) error {
	response, err := http.ReadResponse(reader, request)
	if err != nil {
		return E.Cause(err, "read response")
	}
	if response.StatusCode != http.StatusSwitchingProtocols {
		return statusError(response)
	}
	if !strings.EqualFold(response.Header.Get("Upgrade"), protocol) {
		return E.New("unexpected upgrade protocol: ", response.Header.Get("Upgrade"))
	}
	return nil
}

// http1EarlyConn is returned before the upgrade response arrives.
// Writes go out immediately; the response is verified asynchronously
// under the handshake timeout and checked on the first read.
type http1EarlyConn struct {
	net.Conn
	reader         *std_bufio.Reader
	ready          chan struct{}
	handshakeErr   error
	handshakeState atomic.Int32
	handshakeTimer *time.Timer
	closeOnce      sync.Once
	closeErr       error
}

func newHTTP1EarlyConn(conn net.Conn, request *http.Request, protocol string, timeout time.Duration) *http1EarlyConn {
	earlyConn := &http1EarlyConn{
		Conn:   conn,
		reader: std_bufio.NewReader(conn),
		ready:  make(chan struct{}),
	}
	earlyConn.handshakeTimer = time.AfterFunc(timeout, func() {
		if earlyConn.handshakeState.CompareAndSwap(handshakePending, handshakeTimedOut) {
			_ = earlyConn.closeConn()
		}
	})
	go earlyConn.readResponse(request, protocol)
	return earlyConn
}

func (c *http1EarlyConn) closeConn() error {
	c.closeOnce.Do(func() {
		c.closeErr = c.Conn.Close()
	})
	return c.closeErr
}

func (c *http1EarlyConn) readResponse(request *http.Request, protocol string) {
	defer close(c.ready)
	err := readUpgradeResponse(c.reader, request, protocol)
	c.handshakeTimer.Stop()
	if err != nil {
		switch c.handshakeState.Load() {
		case handshakeTimedOut:
			c.handshakeErr = context.DeadlineExceeded
		case handshakeClosed:
			c.handshakeErr = net.ErrClosed
		default:
			c.handshakeState.CompareAndSwap(handshakePending, handshakeFailed)
			c.handshakeErr = err
		}
		_ = c.closeConn()
		return
	}
	if !c.handshakeState.CompareAndSwap(handshakePending, handshakeSucceeded) {
		if c.handshakeState.Load() == handshakeTimedOut {
			c.handshakeErr = context.DeadlineExceeded
		} else {
			c.handshakeErr = net.ErrClosed
		}
		_ = c.closeConn()
	}
}

func (c *http1EarlyConn) Read(p []byte) (int, error) {
	<-c.ready
	if c.handshakeErr != nil {
		return 0, c.handshakeErr
	}
	return c.reader.Read(p)
}

func (c *http1EarlyConn) Close() error {
	c.handshakeState.CompareAndSwap(handshakePending, handshakeClosed)
	c.handshakeTimer.Stop()
	return c.closeConn()
}

func (c *http1EarlyConn) SetDeadline(time.Time) error {
	return os.ErrInvalid
}

func (c *http1EarlyConn) SetReadDeadline(time.Time) error {
	return os.ErrInvalid
}

func (c *http1EarlyConn) NeedAdditionalReadDeadline() bool {
	return true
}

func (c *Client) openTunnelHTTP2(ctx context.Context, session *http2Session, request tunnelRequest) (net.Conn, error) {
	requestURL := *request.url
	requestURL.Scheme = "https"
	requestURL.Host = c.authority()
	httpRequest := &http.Request{
		Method: http.MethodConnect,
		URL:    &requestURL,
		Host:   c.authority(),
		Header: buildRequestHeader(c.headers, c.authorization, request.originAuthorization),
	}
	httpRequest.Header.Set(":protocol", request.protocol)
	httpRequest.Header.Set("Capsule-Protocol", "?1")
	var (
		streamConn *clientStreamConn
		err        error
	)
	if request.fastOpen {
		streamConn, err = c.roundTripHTTP2FastOpen(ctx, session, httpRequest, request.destination, request.handshakeTimeout)
	} else {
		streamConn, err = c.roundTripHTTP2(ctx, session, httpRequest, request.destination)
	}
	if err != nil {
		return nil, err
	}
	return streamConn, nil
}

func (c *Client) authority() string {
	if c.host != "" {
		return c.host
	}
	if c.authorityOverride != "" {
		return c.authorityOverride
	}
	return c.server.String()
}
