package group

import (
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	U "github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing/common/observable"

	"github.com/stretchr/testify/require"
)

func TestLoadBalanceReferencesProviderCandidates(t *testing.T) {
	static := &preMatchTestOutbound{tag: "static"}
	dynamic := &preMatchTestOutbound{tag: "provider/first"}
	provider := &providerUpdateTestProvider{tag: "provider", outbounds: []adapter.Outbound{dynamic}}
	history := U.NewHistoryStorage()
	hook := observable.NewSubscriber[struct{}](1)
	defer hook.Close()
	history.AddUpdateHook(hook)
	updates, _ := hook.Subscription()
	loadBalance := &LoadBalance{
		Adapter: outbound.NewAdapter("loadbalance", "balance", nil, []string{static.Tag()}),
		outbound: &providerUpdateTestOutboundManager{
			outbounds: map[string]adapter.Outbound{static.Tag(): static},
		},
		providers:    map[string]adapter.Provider{provider.tag: provider},
		providerTags: []string{provider.tag},
	}
	require.Equal(t, []string{static.Tag()}, loadBalance.References())
	loadBalance.group = &LoadBalanceGroup{history: history}
	for _, tag := range []string{"provider/first", "provider/replacement"} {
		provider.outbounds = []adapter.Outbound{&preMatchTestOutbound{tag: tag}}
		require.NoError(t, loadBalance.onProviderUpdated(provider.tag))
		// No health history is present: untested candidates still count as references.
		require.Equal(t, []string{static.Tag(), tag}, loadBalance.References())
		select {
		case <-updates:
		case <-time.After(time.Second):
			t.Fatal("provider update did not notify reference tracking")
		}
	}
}
