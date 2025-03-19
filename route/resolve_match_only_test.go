package route

import (
	"context"
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	R "github.com/sagernet/sing-box/route/rule"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

type matchOnlyDNS struct {
	adapter.DNSRouter
	addresses []netip.Addr
}

func (d *matchOnlyDNS) Lookup(context.Context, string, adapter.DNSQueryOptions) ([]netip.Addr, error) {
	return d.addresses, nil
}

func TestResolveMatchOnlyPreservesDialAddresses(t *testing.T) {
	dns := &matchOnlyDNS{addresses: []netip.Addr{netip.MustParseAddr("10.0.0.1")}}
	router := &Router{dns: dns, logger: logger.NOP()}
	dialAddresses := []netip.Addr{netip.MustParseAddr("192.0.2.1")}
	metadata := adapter.InboundContext{Destination: M.ParseSocksaddr("example.com:443"), DestinationAddresses: dialAddresses}
	require.NoError(t, router.actionResolve(context.Background(), &metadata, &R.RuleActionResolve{MatchOnly: true}))
	require.Equal(t, dialAddresses, metadata.DestinationAddresses)
	require.Equal(t, dns.addresses, metadata.CacheIPs)
	require.Equal(t, uint8(4), metadata.IPVersion)
	dns.addresses = append(dns.addresses, netip.MustParseAddr("2001:db8::1"))
	require.NoError(t, router.actionResolve(context.Background(), &metadata, &R.RuleActionResolve{MatchOnly: true}))
	require.Zero(t, metadata.IPVersion)
}
