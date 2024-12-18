package route

import (
	"context"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	R "github.com/sagernet/sing-box/route/rule"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

func TestPassFallsThroughMatching(t *testing.T) {
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
		})
	}
	selected.selected = &testFlowOutbound{outboundType: C.TypeDirect}
	require.False(t, isPassOutbound(manager, "select"))
	selected.selected = nil
	require.False(t, isPassOutbound(manager, "select"))
}

func (g *testOutboundGroup) Selected() adapter.Outbound { return g.selected }
