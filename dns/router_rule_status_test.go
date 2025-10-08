package dns

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	R "github.com/sagernet/sing-box/route/rule"

	"github.com/stretchr/testify/require"
)

func TestMatchDNSSkipsDisabledRule(t *testing.T) {
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
	}, true)
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
	}, true)
	require.NoError(t, err)

	ctx, metadata := adapter.ExtendContext(context.Background())
	metadata.Domain = "example.com"

	router := &Router{
		logger: logger,
		rules:  []adapter.DNSRule{disabledRule, fallbackRule},
	}
	_, matchedRule, _ := router.matchDNS(ctx, true, -1, true, &adapter.DNSQueryOptions{})
	require.Same(t, fallbackRule, matchedRule)
}
