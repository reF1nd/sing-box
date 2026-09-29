package http

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	stdHTTP "net/http"
	"testing"
	"testing/synctest"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

type fallbackTestHTTP3 struct {
	http3Client
	attempt func(context.Context) error
	calls   int
}

func (c *fallbackTestHTTP3) OpenTunnel(ctx context.Context, _ tunnelRequest) (DatagramStream, error) {
	c.calls++
	return nil, c.attempt(ctx)
}

func (c *fallbackTestHTTP3) DialContext(ctx context.Context, _ M.Socksaddr) (net.Conn, error) {
	c.calls++
	return nil, c.attempt(ctx)
}

type fallbackTestDialer struct {
	N.Dialer
	calls int
}

func (d *fallbackTestDialer) DialContext(ctx context.Context, _ string, _ M.Socksaddr) (net.Conn, error) {
	d.calls++
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		reader := bufio.NewReader(server)
		request, err := stdHTTP.ReadRequest(reader)
		if err != nil {
			return
		}
		if request.Method == stdHTTP.MethodConnect {
			_, err = io.WriteString(server, "HTTP/1.1 200 OK\r\n\r\n")
		} else {
			_, err = io.WriteString(server, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: connect-ip\r\n\r\n")
		}
		if err == nil {
			io.Copy(server, reader)
		}
	}()
	return client, nil
}

func TestHTTP3TimeoutFallsBackWithRemainingDeadline(t *testing.T) {
	for _, tunnel := range []bool{true, false} {
		name := "CONNECT"
		if tunnel {
			name = "CONNECT-IP"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				h3 := &fallbackTestHTTP3{attempt: func(ctx context.Context) error {
					<-ctx.Done()
					return ctx.Err()
				}}
				tcp := &fallbackTestDialer{}
				client := &Client{http3: h3, http1Dialer: tcp, server: M.ParseSocksaddr("example.org:443")}
				ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
				defer cancel()
				started := time.Now()
				var conn io.ReadWriteCloser
				var err error
				if tunnel {
					conn, err = client.OpenTunnel(ctx, "connect-ip", "/")
				} else {
					conn, err = client.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr("example.net:80"))
				}
				require.NoError(t, err)
				defer conn.Close()
				require.Less(t, time.Since(started), 15*time.Second)
				require.NoError(t, ctx.Err())
				require.Equal(t, 1, tcp.calls)
				require.False(t, client.http3Available())
				_, err = conn.Write([]byte("echo"))
				require.NoError(t, err)
				response := make([]byte, 4)
				_, err = io.ReadFull(conn, response)
				require.NoError(t, err)
				require.Equal(t, "echo", string(response))
			})
		})
	}
}

func TestHTTP3FallbackRespectsCancellationAndDisable(t *testing.T) {
	for _, testCase := range []struct {
		name    string
		disable bool
		cancel  bool
	}{
		{name: "strict", disable: true},
		{name: "caller_canceled", cancel: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
				defer cancel()
				h3 := &fallbackTestHTTP3{attempt: func(ctx context.Context) error {
					if testCase.cancel {
						cancel()
					}
					<-ctx.Done()
					return ctx.Err()
				}}
				tcp := &fallbackTestDialer{}
				client := &Client{http3: h3, http1Dialer: tcp, disableVersionFallback: testCase.disable}
				_, err := client.OpenTunnel(ctx, "connect-ip", "/")
				require.ErrorIs(t, err, ctx.Err())
				require.Zero(t, tcp.calls)
				require.True(t, client.http3Available())
			})
		})
	}
}

func TestHTTP3SessionFailureFallsBackOnReconnect(t *testing.T) {
	for _, disable := range []bool{false, true} {
		t.Run(map[bool]string{false: "fallback", true: "strict"}[disable], func(t *testing.T) {
			h3 := &fallbackTestHTTP3{attempt: func(context.Context) error { return io.ErrUnexpectedEOF }}
			tcp := &fallbackTestDialer{}
			client := &Client{http3: h3, http1Dialer: tcp, disableVersionFallback: disable}
			client.ReportTunnelError(context.Canceled)
			require.True(t, client.http3Available())
			client.ReportTunnelError(E.Cause1(ErrHTTP3Unavailable, io.ErrUnexpectedEOF))
			stream, err := client.OpenTunnel(t.Context(), "connect-ip", "/")
			if disable {
				require.ErrorIs(t, err, io.ErrUnexpectedEOF)
				require.Equal(t, 1, h3.calls)
				require.Zero(t, tcp.calls)
			} else {
				require.NoError(t, err)
				stream.Close()
				require.Zero(t, h3.calls)
				require.Equal(t, 1, tcp.calls)
			}
		})
	}
}

func TestHTTP3ApplicationErrorDoesNotFallBack(t *testing.T) {
	applicationError := errors.New("authentication required")
	h3 := &fallbackTestHTTP3{attempt: func(context.Context) error { return applicationError }}
	tcp := &fallbackTestDialer{}
	client := &Client{http3: h3, http1Dialer: tcp}
	_, err := client.OpenTunnel(t.Context(), "connect-ip", "/")
	require.ErrorIs(t, err, applicationError)
	require.Zero(t, tcp.calls)
	require.True(t, client.http3Available())
}
