package rule

import (
	"context"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/observable"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

func TestRuleStatusNotifiesInstanceReferences(t *testing.T) {
	history := urltest.NewHistoryStorage()
	other := urltest.NewHistoryStorage()
	hook := observable.NewSubscriber[struct{}](1)
	defer hook.Close()
	otherHook := observable.NewSubscriber[struct{}](1)
	defer otherHook.Close()
	history.AddUpdateHook(hook)
	other.AddUpdateHook(otherHook)
	updates, _ := hook.Subscription()
	otherUpdates, _ := otherHook.Subscription()
	ctx := service.ContextWithPtr(context.Background(), history)
	logger := log.NewNOPFactory().NewLogger("test")
	routeRule, err := NewDefaultRule(ctx, logger, option.DefaultRule{RuleAction: option.RuleAction{Action: C.RuleActionTypeReject}})
	require.NoError(t, err)
	dnsRule, err := NewDefaultDNSRule(ctx, logger, option.DefaultDNSRule{DNSRuleAction: option.DNSRuleAction{Action: C.RuleActionTypeReject}}, false)
	require.NoError(t, err)
	for _, rule := range []adapter.Rule{routeRule, dnsRule} {
		require.NotEmpty(t, rule.UUID())
		rule.ChangeStatus()
		require.True(t, rule.Disabled())
		select {
		case <-updates:
		case <-time.After(time.Second):
			t.Fatal("reference update missing")
		}
		rule.ChangeStatus()
		require.False(t, rule.Disabled())
		select {
		case <-updates:
		case <-time.After(time.Second):
			t.Fatal("reference update missing")
		}
	}
	select {
	case <-otherUpdates:
		t.Fatal("notification leaked into another instance")
	default:
	}
}
