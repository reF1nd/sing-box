package tun

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

type autoRedirectTestRouter struct {
	adapter.Router
	metadata adapter.InboundContext
}

func (r *autoRedirectTestRouter) RouteConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	r.metadata = metadata
}

func TestAutoRedirectInboundType(t *testing.T) {
	router := &autoRedirectTestRouter{}
	handler := (*autoRedirectHandler)(&Inbound{
		tag:              "tun-in",
		router:           router,
		logger:           logger.NOP(),
		dnsHijackAddress: []netip.Addr{netip.MustParseAddr("172.18.0.2")},
	})
	for _, testCase := range []struct {
		destination string
		inboundType string
		protocol    string
	}{
		{"172.18.0.2:53", C.TypeTun, C.ProtocolDNS},
		{"192.0.2.1:443", C.TypeRedirect, ""},
	} {
		handler.NewConnectionEx(context.Background(), nil, M.ParseSocksaddr("172.18.0.1:10000"), M.ParseSocksaddr(testCase.destination), nil)
		require.Equal(t, testCase.inboundType, router.metadata.InboundType, testCase.destination)
		require.Equal(t, testCase.protocol, router.metadata.Protocol, testCase.destination)
	}
}
