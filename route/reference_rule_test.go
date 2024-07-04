package route

import (
	"context"
	"sync"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/experimental/clashmode"
	"github.com/sagernet/sing-box/option"
	R "github.com/sagernet/sing-box/route/rule"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/service"
	"github.com/stretchr/testify/require"
)

func TestEvaluateMultipleClashModes(t *testing.T) {
	modes := []string{"Rule", "Global"}
	require.Equal(t, staticMatchAlways, evaluateClashMode(modes, "global", false, false))
	require.Equal(t, staticMatchNever, evaluateClashMode(modes, "Direct", false, false))
	require.Equal(t, staticMatchUnknown, evaluateClashMode(modes, "Rule", false, true))
	require.Equal(t, staticMatchNever, evaluateClashMode(modes, "Global", true, false))
	require.Equal(t, staticMatchAlways, evaluateClashMode(modes, "Direct", true, true))
	require.Equal(t, staticMatchAlways, evaluateClashMode(nil, "Rule", false, false))
	// Explicit empty string(s) preserve legacy scalar "no mode restriction" semantics.
	require.Equal(t, staticMatchAlways, evaluateClashMode([]string{""}, "Rule", false, false))
	require.Equal(t, staticMatchUnknown, evaluateClashMode([]string{""}, "Rule", false, true))
	require.Equal(t, staticMatchAlways, evaluateClashMode([]string{"", "Global"}, "global", false, false))
	require.Equal(t, staticMatchNever, evaluateClashMode([]string{"", "Global"}, "Rule", false, false))
}

func TestClashModeNormalizationConsistency(t *testing.T) {
	routeRule, err := json.UnmarshalExtendedContext[option.Rule](context.Background(), []byte(`{"clash_mode":"","domain":["example.com"],"outbound":"direct"}`))
	require.NoError(t, err)
	require.Empty(t, routeRule.DefaultOptions.ClashMode)
	require.Equal(t, staticMatchUnknown, evaluateRule(routeRule, "Rule"))

	builtRouteRule, err := R.NewRule(context.Background(), logger.NOP(), routeRule, false)
	require.NoError(t, err)
	require.NotContains(t, builtRouteRule.String(), "clash_mode=")

	dnsRule, err := json.UnmarshalExtendedContext[option.DNSRule](context.Background(), []byte(`{"clash_mode":["",""],"domain":["example.com"],"server":"local"}`))
	require.NoError(t, err)
	require.Empty(t, dnsRule.DefaultOptions.ClashMode)
	require.Equal(t, staticMatchUnknown, evaluateDNSRule(dnsRule, "Rule"))

	builtDNSRule, err := R.NewDNSRule(context.Background(), logger.NOP(), dnsRule, false, false)
	require.NoError(t, err)
	require.NotContains(t, builtDNSRule.String(), "clash_mode=")

	var dnsOptions option.DNSOptions
	dnsOptions.Rules = []option.DNSRule{dnsRule}
	modes := clashmode.CalculateModeList(option.Options{
		Route: &option.RouteOptions{Rules: []option.Rule{routeRule}},
		DNS:   &dnsOptions,
	})
	require.NotContains(t, modes, "")

	// Empty clash_mode with invert:true has no runtime items so Match returns true;
	// static evaluation must match runtime semantics instead of inverting to Never.
	emptyInvertRoute, err := json.UnmarshalExtendedContext[option.Rule](context.Background(), []byte(`{"clash_mode":[""],"invert":true,"outbound":"wg"}`))
	require.NoError(t, err)
	require.Equal(t, staticMatchAlways, evaluateRule(emptyInvertRoute, "Rule"))
	builtEmptyInvertRoute, err := R.NewRule(context.Background(), logger.NOP(), emptyInvertRoute, false)
	require.NoError(t, err)
	require.True(t, builtEmptyInvertRoute.Match(&adapter.InboundContext{}))

	emptyInvertDNS, err := json.UnmarshalExtendedContext[option.DNSRule](context.Background(), []byte(`{"clash_mode":[""],"invert":true,"server":"local"}`))
	require.NoError(t, err)
	require.Equal(t, staticMatchAlways, evaluateDNSRule(emptyInvertDNS, "Rule"))
	builtEmptyInvertDNS, err := R.NewDNSRule(context.Background(), logger.NOP(), emptyInvertDNS, false, false)
	require.NoError(t, err)
	require.True(t, builtEmptyInvertDNS.Match(&adapter.InboundContext{}))

	// Programmatic struct construction must match JSON validation for empty clash_mode arrays.
	programmaticRoute := option.Rule{
		Type: C.RuleTypeDefault,
		DefaultOptions: option.DefaultRule{
			RawDefaultRule: option.RawDefaultRule{ClashMode: badoption.Listable[string]{""}},
		},
	}
	require.False(t, programmaticRoute.IsValid())
	logicalRoute := option.Rule{
		Type: C.RuleTypeLogical,
		LogicalOptions: option.LogicalRule{
			RawLogicalRule: option.RawLogicalRule{
				Mode:  C.LogicalTypeOr,
				Rules: []option.Rule{programmaticRoute},
			},
		},
	}
	require.False(t, logicalRoute.IsValid())

	programmaticDNS := option.DNSRule{
		Type: C.RuleTypeDefault,
		DefaultOptions: option.DefaultDNSRule{
			RawDefaultDNSRule: option.RawDefaultDNSRule{ClashMode: badoption.Listable[string]{""}},
		},
	}
	require.False(t, programmaticDNS.IsValid())
}

func TestClashModeItemSnapshotConsistencyUnderConcurrentSetMode(t *testing.T) {
	ctx := context.Background()
	manager := clashmode.NewManager(ctx, logger.NOP(), "Rule", []string{"Rule", "Global"})
	ctx = service.ContextWithPtr(ctx, manager)
	item := R.NewClashModeItem(ctx, []string{"Rule", "Global"})
	require.NoError(t, item.Start())

	var wg sync.WaitGroup
	done := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 5000; i++ {
			if i%2 == 0 {
				manager.SetMode("Global")
			} else {
				manager.SetMode("Rule")
			}
		}
		close(done)
	}()

	var metadata adapter.InboundContext
	for {
		select {
		case <-done:
			wg.Wait()
			return
		default:
			require.True(t, item.Match(&metadata), "snapshot match across [Rule, Global] must never miss while toggling between them")
		}
	}
}
