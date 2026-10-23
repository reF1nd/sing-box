package http

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/pipe"

	"golang.org/x/net/http2"
)

func (c *Client) acquireHTTP2(ctx context.Context) (*http2ClientConn, net.Conn, error) {
	c.http2Access.Lock()
	defer c.http2Access.Unlock()
	c.http2Conns = slices.DeleteFunc(c.http2Conns, func(it *http2ClientConn) bool { return it.isClosed() })
	for _, clientConn := range c.http2Conns {
		if clientConn.reserveNewRequest() {
			return clientConn, nil, nil
		}
	}
	conn, err := c.tlsDialer.DialTLSContext(adapter.ContextForMultiplexSession(ctx), c.server)
	if err != nil {
		return nil, nil, err
	}
	if conn.ConnectionState().NegotiatedProtocol != http2.NextProtoTLS {
		if !c.disableVersionFallback {
			c.http2Unsupported.Store(true)
		}
		return nil, conn, nil
	}
	clientConn, err := newHTTP2ClientConn(c.http2Transport, conn)
	if err != nil {
		conn.Close()
		return nil, nil, E.Cause(err, "create HTTP/2 connection")
	}
	clientConn.reserveNewRequest()
	c.http2Conns = append(c.http2Conns, clientConn)
	return clientConn, nil, nil
}

func (c *Client) connectHTTP2(ctx context.Context, clientConn *http2ClientConn, destination M.Socksaddr) (net.Conn, error) {
	request := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Host: destination.String()},
		Host:   destination.String(),
		Header: buildRequestHeader(c.headers, c.authorization, false),
	}
	streamConn, err := c.roundTripHTTP2(ctx, clientConn, request, destination)
	if err != nil {
		return nil, err
	}
	return newClientTunnelConn(streamConn), nil
}

func (c *Client) roundTripHTTP2(ctx context.Context, clientConn *http2ClientConn, request *http.Request, destination M.Socksaddr) (*clientStreamConn, error) {
	pipeReader, pipeWriter := pipe.Pipe()
	streamCtx, cancel := context.WithCancel(context.Background())
	request.Body = pipeReader
	request = request.WithContext(streamCtx)
	stop := context.AfterFunc(ctx, cancel)
	response, err := clientConn.roundTrip(request)
	stopped := stop()
	if err == nil && !stopped {
		response.Body.Close()
		err = ctx.Err()
	}
	if err != nil {
		cancel()
		pipeWriter.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, http2RoundTripError(err)
	}
	if response.StatusCode != http.StatusOK {
		response.Body.Close()
		cancel()
		pipeWriter.Close()
		return nil, statusError(response)
	}
	return &clientStreamConn{
		reader:     response.Body,
		writer:     pipeWriter,
		cancel:     cancel,
		localAddr:  M.Socksaddr{},
		remoteAddr: destination,
	}, nil
}

func http2RoundTripError(err error) error {
	// golang.org/x/net/http2 has no exported sentinel for a peer that lacks
	// SETTINGS_ENABLE_CONNECT_PROTOCOL; it returns errExtendedConnectNotSupported
	// ("net/http: extended connect not supported by peer") from RoundTrip.
	if strings.Contains(err.Error(), "extended connect not supported") {
		return E.Cause1(errExtendedConnectUnsupported, err)
	}
	return E.Cause(err, "HTTP/2 CONNECT")
}

// roundTripHTTP2FastOpen returns once the transport starts reading the request body.
// The transport does that only after the extended CONNECT check passed and HEADERS
// were written, so a peer without extended CONNECT still fails here and keeps the
// HTTP/1 fallback working. The response is checked on the first read.
func (c *Client) roundTripHTTP2FastOpen(ctx context.Context, clientConn *http2ClientConn, request *http.Request, destination M.Socksaddr) (*clientStreamConn, error) {
	pipeReader, pipeWriter := pipe.Pipe()
	streamCtx, cancel := context.WithCancel(context.Background())
	bodyStarted := make(chan struct{})
	request.Body = &http2NotifyBody{ReadCloser: pipeReader, notify: sync.OnceFunc(func() { close(bodyStarted) })}
	request = request.WithContext(streamCtx)
	response := &http2EarlyResponse{ready: make(chan struct{})}
	go func() {
		httpResponse, err := clientConn.roundTrip(request)
		if err != nil {
			response.err = http2RoundTripError(err)
		} else if httpResponse.StatusCode != http.StatusOK {
			httpResponse.Body.Close()
			response.err = statusError(httpResponse)
		} else {
			response.body = httpResponse.Body
		}
		if response.err != nil {
			cancel()
			pipeWriter.Close()
		}
		close(response.ready)
	}()
	select {
	case <-bodyStarted:
	case <-response.ready:
		if response.err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, response.err
		}
	case <-ctx.Done():
		cancel()
		pipeWriter.Close()
		response.Close()
		return nil, ctx.Err()
	}
	return &clientStreamConn{
		reader:     response,
		writer:     pipeWriter,
		cancel:     cancel,
		localAddr:  M.Socksaddr{},
		remoteAddr: destination,
	}, nil
}

type http2NotifyBody struct {
	io.ReadCloser
	notify func()
}

func (b *http2NotifyBody) Read(p []byte) (int, error) {
	b.notify()
	return b.ReadCloser.Read(p)
}

// http2EarlyResponse is the response body of a fast open stream.
// Reads wait for the response and fail if it was not successful.
type http2EarlyResponse struct {
	ready chan struct{}
	body  io.ReadCloser
	err   error
}

func (r *http2EarlyResponse) Read(p []byte) (int, error) {
	<-r.ready
	if r.err != nil {
		return 0, r.err
	}
	return r.body.Read(p)
}

func (r *http2EarlyResponse) Close() error {
	select {
	case <-r.ready:
		if r.body != nil {
			return r.body.Close()
		}
		return nil
	default:
	}
	// The stream is being canceled, so the round trip finishes shortly.
	go func() {
		<-r.ready
		if r.body != nil {
			r.body.Close()
		}
	}()
	return nil
}

func (c *Client) connectAndClose(ctx context.Context, conn net.Conn, destination M.Socksaddr) (net.Conn, error) {
	result, err := c.connect(ctx, conn, destination)
	if err != nil {
		conn.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	return result, nil
}
