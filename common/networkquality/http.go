package networkquality

import (
	"context"
	"net"
	"net/http"
	"strings"

	C "github.com/sagernet/sing-box/constant"
	sBufio "github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// NewHTTPClient creates an http.Client that dials through the given dialer.
// The dialer should already handle DNS resolution if needed.
func NewHTTPClient(dialer N.Dialer) *http.Client {
	transport := &http.Transport{
		ForceAttemptHTTP2:   true,
		TLSHandshakeTimeout: C.TCPTimeout,
	}
	if dialer != nil {
		transport.DialContext = func(ctx context.Context, network string, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, M.ParseSocksaddr(addr))
		}
	}
	return &http.Client{Transport: transport}
}

func baseTransportFromClient(client *http.Client) (*http.Transport, error) {
	if client == nil {
		return nil, E.New("http client is nil")
	}
	if client.Transport == nil {
		return http.DefaultTransport.(*http.Transport).Clone(), nil
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		return nil, E.New("http client transport must be *http.Transport")
	}
	return transport.Clone(), nil
}

func newMeasurementClient(
	baseClient *http.Client,
	connectEndpoint string,
	singleConnection bool,
	disableKeepAlives bool,
	readCounters []N.CountFunc,
	writeCounters []N.CountFunc,
) (*http.Client, error) {
	transport, err := baseTransportFromClient(baseClient)
	if err != nil {
		return nil, err
	}
	transport.DisableCompression = true
	transport.DisableKeepAlives = disableKeepAlives
	if singleConnection {
		transport.MaxConnsPerHost = 1
		transport.MaxIdleConnsPerHost = 1
		transport.MaxIdleConns = 1
	}

	baseDialContext := transport.DialContext
	if baseDialContext == nil {
		dialer := &net.Dialer{}
		baseDialContext = dialer.DialContext
	}
	connectEndpoint = strings.TrimSpace(connectEndpoint)
	transport.DialContext = func(ctx context.Context, network string, addr string) (net.Conn, error) {
		dialAddr := addr
		if connectEndpoint != "" {
			dialAddr = rewriteDialAddress(addr, connectEndpoint)
		}
		conn, dialErr := baseDialContext(ctx, network, dialAddr)
		if dialErr != nil {
			return nil, dialErr
		}
		if len(readCounters) > 0 || len(writeCounters) > 0 {
			return sBufio.NewCounterConn(conn, readCounters, writeCounters), nil
		}
		return conn, nil
	}

	return &http.Client{
		Transport:     transport,
		CheckRedirect: baseClient.CheckRedirect,
		Jar:           baseClient.Jar,
		Timeout:       baseClient.Timeout,
	}, nil
}

func rewriteDialAddress(addr string, connectEndpoint string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	endpointHost, endpointPort, err := net.SplitHostPort(connectEndpoint)
	if err == nil {
		host = endpointHost
		if endpointPort != "" {
			port = endpointPort
		}
	} else if connectEndpoint != "" {
		host = connectEndpoint
	}
	return net.JoinHostPort(host, port)
}
