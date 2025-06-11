package anytls

import (
	"context"
	"net"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

func TestInboundFallbackSelection(t *testing.T) {
	for _, testCase := range []struct {
		name, alpn, want           string
		defaultEnabled, mapEnabled bool
	}{
		{"default", "", "default.example:80", true, false},
		{"alpn", "h2", "alpn.example:80", true, true},
		{"alpn-only", "h2", "alpn.example:80", false, true},
		{"unknown-alpn", "http/1.1", "", true, true},
		{"no-alpn", "", "default.example:80", true, true},
		{"no-default", "", "", false, true},
		{"disabled", "", "", false, false},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			router := &fallbackTestRouter{}
			inbound := &Inbound{router: router, logger: logger.NOP()}
			if testCase.defaultEnabled {
				inbound.fallbackAddr = M.ParseSocksaddr("default.example:80")
			}
			if testCase.mapEnabled {
				inbound.fallbackAddrTLSNextProto = map[string]M.Socksaddr{"h2": M.ParseSocksaddr("alpn.example:80")}
			}
			conn := &fallbackTestConn{alpn: testCase.alpn}
			callbacks := 0
			inbound.fallbackConnection(context.Background(), conn, adapter.InboundContext{}, func(err error) {
				require.Error(t, err)
				callbacks++
			})
			if testCase.want == "" {
				require.True(t, conn.closed)
				require.Equal(t, 1, callbacks)
				require.False(t, router.destination.IsValid())
			} else {
				require.Equal(t, M.ParseSocksaddr(testCase.want), router.destination)
				require.False(t, conn.closed)
				require.Zero(t, callbacks)
			}
		})
	}
}

func TestInboundALPNFallbackRequiresTLS(t *testing.T) {
	_, err := NewInbound(context.Background(), nil, logger.NOP(), "test", option.AnyTLSInboundOptions{
		FallbackForALPN: map[string]*option.ServerOptions{"h2": {Server: "127.0.0.1", ServerPort: 80}},
	})
	require.ErrorContains(t, err, "fallback for ALPN is not supported without TLS")
}

type fallbackTestRouter struct {
	adapter.ConnectionRouterEx
	destination M.Socksaddr
}

func (r *fallbackTestRouter) RouteConnectionEx(_ context.Context, _ net.Conn, metadata adapter.InboundContext, _ N.CloseHandlerFunc) {
	r.destination = metadata.Destination
}

type fallbackTestConn struct {
	tls.Conn
	alpn   string
	closed bool
}

func (c *fallbackTestConn) ConnectionState() tls.ConnectionState {
	return tls.ConnectionState{NegotiatedProtocol: c.alpn}
}
func (c *fallbackTestConn) Close() error { c.closed = true; return nil }

func (c *fallbackTestConn) NetConn() net.Conn { return nil }
