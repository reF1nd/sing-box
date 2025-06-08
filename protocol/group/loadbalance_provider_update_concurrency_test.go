package group

import (
	"context"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	U "github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/log"

	"github.com/stretchr/testify/require"
)

func TestLoadBalanceProviderConcurrentUpdates(t *testing.T) {
	firstOutbound := &providerUpdateTestOutbound{tag: "first/outbound"}
	secondOutbound := &providerUpdateTestOutbound{tag: "second/outbound"}
	providers := map[string]adapter.Provider{
		"first":  &providerUpdateTestProvider{tag: "first", outbounds: []adapter.Outbound{firstOutbound}},
		"second": &providerUpdateTestProvider{tag: "second", outbounds: []adapter.Outbound{secondOutbound}},
	}
	outboundManager := &providerUpdateTestOutboundManager{
		outbounds: map[string]adapter.Outbound{
			firstOutbound.Tag():  firstOutbound,
			secondOutbound.Tag(): secondOutbound,
		},
	}
	providerTags := []string{"first", "second"}
	expectedTags := []string{firstOutbound.Tag(), secondOutbound.Tag()}
	group := new(LoadBalanceGroup)
	group.storeOutbounds([]adapter.Outbound{firstOutbound, secondOutbound})
	loadBalance := &LoadBalance{
		outbound:       outboundManager,
		group:          group,
		providers:      providers,
		providerTags:   providerTags,
		outboundsCache: make(map[string][]adapter.Outbound),
	}

	runConcurrentProviderUpdates(t, loadBalance.onProviderUpdated, func() {
		_ = loadBalance.All()
	})
	require.Equal(t, expectedTags, loadBalance.All())
}

func TestLoadBalanceGroupReturnsWhenDialIgnoresContext(t *testing.T) {
	release := make(chan struct{})
	outbound := &providerUpdateBlockingOutbound{tag: "blocking", release: release}
	outboundManager := &providerUpdateTestOutboundManager{
		outbounds: map[string]adapter.Outbound{outbound.Tag(): outbound},
	}
	group := &LoadBalanceGroup{
		ctx:      context.Background(),
		outbound: outboundManager,
		logger:   log.NewNOPFactory().NewLogger("loadbalance"),
		history:  U.NewHistoryStorage(),
	}
	group.storeOutbounds([]adapter.Outbound{outbound})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	_, err := group.urlTestWait(ctx, true)
	close(release)
	require.NoError(t, err)
	require.True(t, group.checking.TryLock(), "LoadBalance checking lock was not released")
	group.checking.Unlock()
}
