package route

import (
	"context"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	R "github.com/sagernet/sing-box/route/rule"

	"github.com/stretchr/testify/require"
)

func TestDisabledRuleFallsThroughPreMatchAndMatch(t *testing.T) {
	router, metadata := newPreMatchQUICRouter(t, time.Minute)
	router.outbound = &testL3OutboundManager{outbounds: map[string]adapter.Outbound{}}
	disabled := &preMatchQUICRule{action: &R.RuleActionRoute{Outbound: "disabled"}, disabled: true}
	bypass := &preMatchQUICRule{action: &R.RuleActionBypass{}}
	next := &preMatchQUICRule{action: &R.RuleActionRoute{Outbound: "next"}}
	router.rules = []adapter.Rule{disabled, bypass, next}
	require.Equal(t, adapter.PreMatchBypass, router.PreMatch(metadata, nil).Action)
	matched, _, _, _, err := router.matchRule(context.Background(), &metadata, nil, nil)
	require.NoError(t, err)
	require.Same(t, next, matched)
}

func TestDisabledRuleReferenceReachability(t *testing.T) {
	runtime := []*preMatchQUICRule{{disabled: true}, {}}
	routeOptions := []option.Rule{}
	dnsOptions := []option.DNSRule{}
	for _, tag := range []string{"disabled", "fallback"} {
		routeOptions = append(routeOptions, option.Rule{Type: C.RuleTypeDefault, DefaultOptions: option.DefaultRule{RuleAction: option.RuleAction{Action: C.RuleActionTypeRoute, RouteOptions: option.RouteActionOptions{Outbound: tag}}}})
		dnsOptions = append(dnsOptions, option.DNSRule{Type: C.RuleTypeDefault, DefaultOptions: option.DefaultDNSRule{DNSRuleAction: option.DNSRuleAction{Action: C.RuleActionTypeRoute, RouteOptions: option.DNSRouteActionOptions{Server: tag}}}})
	}
	manager := &testL3OutboundManager{outbounds: map[string]adapter.Outbound{}}
	var outbounds, transports []string
	require.True(t, collectRuleReferences(enabledRuleOptions(routeOptions, runtime), "", manager, &outbounds, &transports))
	require.Equal(t, []string{"fallback"}, outbounds)
	require.True(t, collectDNSRuleReferences(enabledRuleOptions(dnsOptions, runtime), "", &transports))
	require.Equal(t, []string{"fallback"}, transports)
	runtime[1].disabled = true
	require.False(t, collectRuleReferences(enabledRuleOptions(routeOptions, runtime), "", manager, &outbounds, &transports))
	require.False(t, collectDNSRuleReferences(enabledRuleOptions(dnsOptions, runtime), "", &transports))
	runtime[0].disabled = false
	outbounds = nil
	require.True(t, collectRuleReferences(enabledRuleOptions(routeOptions, runtime), "", manager, &outbounds, &transports))
	require.Equal(t, []string{"disabled"}, outbounds)
}
