package route

import (
	"context"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
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
