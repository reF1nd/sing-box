package dns

import (
	"context"
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	R "github.com/sagernet/sing-box/route/rule"
	M "github.com/sagernet/sing/common/metadata"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestDNSRulesIgnoreConnectionSniffHost(t *testing.T) {
	for _, lookup := range []bool{false, true} {
		for _, testCase := range []struct {
			name string
			rule option.RawDefaultDNSRule
		}{
			{"domain", option.RawDefaultDNSRule{Domain: []string{"query.example"}}},
			{"suffix", option.RawDefaultDNSRule{DomainSuffix: []string{"query.example"}}},
			{"keyword", option.RawDefaultDNSRule{DomainKeyword: []string{"query"}}},
			{"regex", option.RawDefaultDNSRule{DomainRegex: []string{`^query\.example$`}}},
		} {
			name := "exchange/" + testCase.name
			if lookup {
				name = "lookup/" + testCase.name
			}
			t.Run(name, func(t *testing.T) {
				selected := &fakeDNSTransport{tag: "selected", address: netip.MustParseAddr("192.0.2.1")}
				fallback := &fakeDNSTransport{tag: "final", address: netip.MustParseAddr("192.0.2.2")}
				router := raceTestRouter(t, selected, fallback)
				rawRule := routeRule("selected", false)
				rawRule.DefaultOptions.RawDefaultDNSRule = testCase.rule
				router.rules = raceTestRules(t, []option.DNSRule{rawRule})
				parent := adapter.InboundContext{
					Destination: M.ParseSocksaddr("original.example:443"),
					SniffHost:   "sni.example",
					Domain:      "reverse.example",
				}
				ctx := adapter.WithContext(context.Background(), &parent)
				if lookup {
					addresses, err := router.Lookup(ctx, "query.example", adapter.DNSQueryOptions{Strategy: C.DomainStrategyIPv4Only})
					require.NoError(t, err)
					require.Equal(t, []netip.Addr{selected.address}, addresses)
				} else {
					message := new(mDNS.Msg)
					message.SetQuestion("query.example.", mDNS.TypeA)
					_, err := router.Exchange(ctx, message, adapter.DNSQueryOptions{})
					require.NoError(t, err)
				}
				require.Positive(t, selected.queryCount.Load())
				require.Zero(t, fallback.queryCount.Load())
				require.Equal(t, "sni.example", parent.SniffHost)
				require.Equal(t, "reverse.example", parent.Domain)
				require.Equal(t, "original.example", parent.Destination.Fqdn)
			})
		}
	}
}

func TestDNSQueryMetadataMatchesHeadlessDomains(t *testing.T) {
	router := raceTestRouter(t)
	parent := &adapter.InboundContext{SniffHost: "sni.example"}
	message := new(mDNS.Msg)
	message.SetQuestion("query.example.", mDNS.TypeA)
	exchange, _, err := router.prepareExchange(adapter.WithContext(context.Background(), parent), message)
	require.NoError(t, err)
	for _, options := range []option.DefaultHeadlessRule{
		{Domain: []string{"query.example"}},
		{AdGuardDomain: []string{"||query.example^"}},
	} {
		rule, err := R.NewDefaultHeadlessRule(context.Background(), options)
		require.NoError(t, err)
		exchange.metadata.ResetRuleCache()
		require.True(t, rule.Match(exchange.metadata))
	}
	require.Equal(t, "sni.example", parent.SniffHost)
}
