package dns

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	R "github.com/sagernet/sing-box/route/rule"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestExchangeWithRulesSkipsDisabledRule(t *testing.T) {
	t.Parallel()

	logger := log.NewNOPFactory().NewLogger("dns")
	disabledRule, err := R.NewDNSRule(context.Background(), logger, option.DNSRule{
		Type: C.RuleTypeDefault,
		DefaultOptions: option.DefaultDNSRule{
			RawDefaultDNSRule: option.RawDefaultDNSRule{
				Domain: []string{"example.com"},
			},
			DNSRuleAction: option.DNSRuleAction{
				Action: C.RuleActionTypeRoute,
				RouteOptions: option.DNSRouteActionOptions{
					Server: "fakeip",
				},
			},
		},
	}, true, false)
	require.NoError(t, err)
	disabledRule.ChangeStatus()
	require.True(t, disabledRule.Disabled())

	fallbackRule, err := R.NewDNSRule(context.Background(), logger, option.DNSRule{
		Type: C.RuleTypeDefault,
		DefaultOptions: option.DefaultDNSRule{
			RawDefaultDNSRule: option.RawDefaultDNSRule{
				Domain: []string{"example.com"},
			},
			DNSRuleAction: option.DNSRuleAction{
				Action: C.RuleActionTypePredefined,
			},
		},
	}, true, false)
	require.NoError(t, err)

	ctx, metadata := adapter.ExtendContext(context.Background())
	metadata.Domain = "example.com"
	message := new(mDNS.Msg)
	message.SetQuestion("example.com.", mDNS.TypeA)

	router := &Router{logger: logger}
	result := router.exchangeWithRules(ctx, []adapter.DNSRule{disabledRule, fallbackRule}, message, adapter.DNSQueryOptions{}, true)
	require.NoError(t, result.err)
	require.NotNil(t, result.response)
	require.Equal(t, mDNS.RcodeSuccess, result.response.Rcode)
}
