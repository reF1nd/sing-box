package route

import (
	"context"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	R "github.com/sagernet/sing-box/route/rule"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

func TestPassFallsThroughMatchingAndReferences(t *testing.T) {
	pass := &testFlowOutbound{tag: "pass", outboundType: C.TypePass}
	selected := &testOutboundGroup{Outbound: &testFlowOutbound{tag: "select", outboundType: C.TypeSelector}, selected: pass}
	manager := &testL3OutboundManager{outbounds: map[string]adapter.Outbound{"pass": pass, "select": selected}}
	for _, tag := range []string{"pass", "select"} {
		t.Run(tag, func(t *testing.T) {
			router, metadata := newPreMatchQUICRouter(t, time.Minute)
			router.outbound = manager
			first := &preMatchQUICRule{action: &R.RuleActionRoute{Outbound: tag, RuleActionRouteOptions: R.RuleActionRouteOptions{OverrideAddress: M.ParseSocksaddr("192.0.2.1:0")}}}
			last := &preMatchQUICRule{action: &R.RuleActionBypass{}}
			next := &preMatchQUICRule{action: &R.RuleActionRoute{Outbound: "next"}}
			router.rules = []adapter.Rule{first, last, next}
			destination := metadata.Destination
			require.Equal(t, adapter.PreMatchBypass, router.PreMatch(metadata, nil).Action)
			matched, _, _, _, err := router.matchRule(context.Background(), &metadata, nil, nil)
			require.NoError(t, err)
			require.Same(t, next, matched)
			require.Equal(t, destination, metadata.Destination)
			rules := []option.Rule{{Type: C.RuleTypeDefault, DefaultOptions: option.DefaultRule{RuleAction: option.RuleAction{Action: C.RuleActionTypeRoute, RouteOptions: option.RouteActionOptions{Outbound: tag}}}}}
			var outbounds, transports []string
			require.False(t, collectRuleReferences(rules, "", manager, &outbounds, &transports), "pass must keep the default reachable")
			require.Equal(t, []string{tag}, outbounds)
			rules = append(rules, option.Rule{Type: C.RuleTypeDefault, DefaultOptions: option.DefaultRule{RuleAction: option.RuleAction{Action: C.RuleActionTypeRoute, RouteOptions: option.RouteActionOptions{Outbound: "next"}}}})
			outbounds = nil
			require.True(t, collectRuleReferences(rules, "", manager, &outbounds, &transports))
			require.Equal(t, []string{tag, "next"}, outbounds)
		})
	}
	selected.selected = &testFlowOutbound{outboundType: C.TypeDirect}
	require.False(t, isPassOutbound(manager, "select"))
	selected.selected = nil
	require.False(t, isPassOutbound(manager, "select"))
}
