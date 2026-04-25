package adapter

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/common/interrupt"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestDNSResponseAddressesUnmapsHTTPSIPv4Hints(t *testing.T) {
	t.Parallel()

	ipv4Hint := net.ParseIP("1.1.1.1")
	require.NotNil(t, ipv4Hint)

	response := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Response: true,
			Rcode:    dns.RcodeSuccess,
		},
		Answer: []dns.RR{
			&dns.HTTPS{
				SVCB: dns.SVCB{
					Hdr: dns.RR_Header{
						Name:   dns.Fqdn("example.com"),
						Rrtype: dns.TypeHTTPS,
						Class:  dns.ClassINET,
						Ttl:    60,
					},
					Priority: 1,
					Target:   ".",
					Value: []dns.SVCBKeyValue{
						&dns.SVCBIPv4Hint{Hint: []net.IP{ipv4Hint}},
					},
				},
			},
		},
	}

	addresses := DNSResponseAddresses(response)
	require.Equal(t, []netip.Addr{netip.MustParseAddr("1.1.1.1")}, addresses)
	require.True(t, addresses[0].Is4())
}

func TestContextForMultiplexSessionClearsInterruptMarks(t *testing.T) {
	t.Parallel()

	ctx := interrupt.ContextWithIsExternalConnection(context.Background(), true)
	ctx = interrupt.ContextWithIsResourceDownload(ctx, true)
	ctx = ContextForMultiplexSession(ctx)
	require.False(t, interrupt.IsExternalConnectionFromContext(ctx))
	require.False(t, interrupt.IsResourceDownloadFromContext(ctx))
}
