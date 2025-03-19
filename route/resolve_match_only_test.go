package route

import (
	"context"
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	R "github.com/sagernet/sing-box/route/rule"
	"github.com/sagernet/sing/common/json/badoption"
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

	cachePrefix := badoption.Prefixable(netip.MustParsePrefix("10.0.0.0/8"))
	cacheCIDR, err := R.NewIPCIDRItem(false, []*badoption.Prefixable{&cachePrefix})
	require.NoError(t, err)
	require.True(t, cacheCIDR.Match(&metadata))

	dialPrefix := badoption.Prefixable(netip.MustParsePrefix("192.0.2.0/24"))
	dialCIDR, err := R.NewIPCIDRItem(false, []*badoption.Prefixable{&dialPrefix})
	require.NoError(t, err)
	require.True(t, dialCIDR.Match(&metadata))

	otherPrefix := badoption.Prefixable(netip.MustParsePrefix("203.0.113.0/24"))
	otherCIDR, err := R.NewIPCIDRItem(false, []*badoption.Prefixable{&otherPrefix})
	require.NoError(t, err)
	require.False(t, otherCIDR.Match(&metadata))

	dns.addresses = append(dns.addresses, netip.MustParseAddr("2001:db8::1"))
	require.NoError(t, router.actionResolve(context.Background(), &metadata, &R.RuleActionResolve{MatchOnly: true}))
	require.Zero(t, metadata.IPVersion)
}
