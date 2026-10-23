package http

import (
	std_bufio "bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type tunnelRequest struct {
	protocol            string
	url                 *url.URL
	destination         M.Socksaddr
	originAuthorization bool
	// fastOpen returns the tunnel once the request is sent, before the response
	// arrives. The response is checked on the first read.
	fastOpen bool
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
	if c.http3Available() {
		attemptCtx, cancel := c.http3AttemptContext(ctx)
		stream, err := c.http3.OpenTunnel(attemptCtx, request)
		err = http3AttemptError(ctx, attemptCtx, err)
		cancel()
		if err == nil {
			c.clearHTTP3Broken()
			return nil, stream, nil
		}
		if c.disableVersionFallback || !errors.Is(err, ErrHTTP3Unavailable) {
			return nil, nil, err
		}
		c.markHTTP3Broken()
	}
	if !extendedConnectAvailable && c.tlsDialer != nil && c.disableVersionFallback {
		return nil, nil, errExtendedConnectUnavailable
	}
	if extendedConnectAvailable && c.tlsDialer != nil && !c.http2Unsupported.Load() && !c.http2ExtendedConnectUnsupported.Load() {
		clientConn, conn, err := c.acquireHTTP2(ctx)
		if err != nil {
			return nil, nil, err
		}
		if clientConn != nil {
			streamConn, connectErr := c.openTunnelHTTP2(ctx, clientConn, request)
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
	tunnelConn, err := c.openTunnelHTTP1(ctx, conn, request)
	if err != nil {
		conn.Close()
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
		return nil, nil, err
	}
	return tunnelConn, nil, nil
}

func (c *Client) openTunnelHTTP1(ctx context.Context, conn net.Conn, request tunnelRequest) (net.Conn, error) {
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
		return newHTTP1EarlyConn(conn, httpRequest, request.protocol), nil
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
// Writes go out immediately; the first read checks the response.
type http1EarlyConn struct {
	net.Conn
	reader    *std_bufio.Reader
	handshake func() error
}

func newHTTP1EarlyConn(conn net.Conn, request *http.Request, protocol string) *http1EarlyConn {
	reader := std_bufio.NewReader(conn)
	return &http1EarlyConn{
		Conn:   conn,
		reader: reader,
		handshake: sync.OnceValue(func() error {
			err := readUpgradeResponse(reader, request, protocol)
			if err != nil {
				conn.Close()
			}
			return err
		}),
	}
}

func (c *http1EarlyConn) Read(p []byte) (int, error) {
	err := c.handshake()
	if err != nil {
		return 0, err
	}
	return c.reader.Read(p)
}

func (c *Client) openTunnelHTTP2(ctx context.Context, clientConn *http2ClientConn, request tunnelRequest) (net.Conn, error) {
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
		streamConn, err = c.roundTripHTTP2FastOpen(ctx, clientConn, httpRequest, request.destination)
	} else {
		streamConn, err = c.roundTripHTTP2(ctx, clientConn, httpRequest, request.destination)
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
