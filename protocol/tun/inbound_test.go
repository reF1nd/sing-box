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

	// Explicit dns_address with hijack: NewInbound sets redirectDNSAddress,
	// leaves dnsHijackByPort=false and Start leaves dnsHijackAddress empty so
	// rewritten DNS traffic flows through route rules as TypeRedirect.
	explicitHandler := (*autoRedirectHandler)(&Inbound{
		tag:                "tun-explicit",
		router:             router,
		logger:             logger.NOP(),
		redirectDNSAddress: netip.MustParseAddr("fdfe:dcba:9876::2"),
	})
	for _, testCase := range []struct {
		source      string
		destination string
		wantDest    string
		inboundType string
		protocol    string
	}{
		{"[fe80::1]:10000", "[2001:4860:4860::8888]:53", "[fdfe:dcba:9876::2]:53", C.TypeRedirect, ""},
		{"172.18.0.1:10000", "192.0.2.1:443", "192.0.2.1:443", C.TypeRedirect, ""},
	} {
		explicitHandler.NewConnectionEx(context.Background(), nil, M.ParseSocksaddr(testCase.source), M.ParseSocksaddr(testCase.destination), nil)
		require.Equal(t, testCase.wantDest, router.metadata.Destination.String(), testCase.destination)
		require.Equal(t, testCase.inboundType, router.metadata.InboundType, testCase.destination)
		require.Equal(t, testCase.protocol, router.metadata.Protocol, testCase.destination)
	}

	// Implicit dns_address with hijack: dnsHijackByPort=true and dnsHijackAddress
	// is populated from TUN prefixes; port-53 TCP is marked TypeTun/ProtocolDNS.
	implicitHijackHandler := (*autoRedirectHandler)(&Inbound{
		tag:              "tun-implicit-hijack",
		router:           router,
		logger:           logger.NOP(),
		dnsHijackByPort:  true,
		dnsHijackAddress: []netip.Addr{netip.MustParseAddr("172.18.0.2"), netip.MustParseAddr("fdfe:dcba:9876::2")},
	})
	for _, testCase := range []struct {
		source      string
		destination string
		inboundType string
		protocol    string
	}{
		{"172.18.0.1:10000", "172.18.0.2:53", C.TypeTun, C.ProtocolDNS},
		{"[fe80::1]:10000", "[2001:4860:4860::8888]:53", C.TypeTun, C.ProtocolDNS},
		{"172.18.0.1:10000", "8.8.8.8:53", C.TypeTun, C.ProtocolDNS},
		{"172.18.0.1:10000", "8.8.8.8:443", C.TypeRedirect, ""},
	} {
		implicitHijackHandler.NewConnectionEx(context.Background(), nil, M.ParseSocksaddr(testCase.source), M.ParseSocksaddr(testCase.destination), nil)
		require.Equal(t, testCase.destination, router.metadata.Destination.String(), testCase.destination)
		require.Equal(t, testCase.inboundType, router.metadata.InboundType, testCase.destination)
		require.Equal(t, testCase.protocol, router.metadata.Protocol, testCase.destination)
	}

	// Implicit dns_address with native mode: only TUN DNS addresses match hijack.
	implicitNativeHandler := (*autoRedirectHandler)(&Inbound{
		tag:              "tun-implicit-native",
		router:           router,
		logger:           logger.NOP(),
		dnsHijackAddress: []netip.Addr{netip.MustParseAddr("172.18.0.2"), netip.MustParseAddr("fdfe:dcba:9876::2")},
	})
	implicitNativeHandler.NewConnectionEx(context.Background(), nil, M.ParseSocksaddr("172.18.0.1:10000"), M.ParseSocksaddr("172.18.0.2:53"), nil)
	require.Equal(t, C.TypeTun, router.metadata.InboundType)
	require.Equal(t, C.ProtocolDNS, router.metadata.Protocol)
	implicitNativeHandler.NewConnectionEx(context.Background(), nil, M.ParseSocksaddr("172.18.0.1:10000"), M.ParseSocksaddr("8.8.8.8:53"), nil)
	require.Equal(t, C.TypeRedirect, router.metadata.InboundType)
	require.Empty(t, router.metadata.Protocol)
}
