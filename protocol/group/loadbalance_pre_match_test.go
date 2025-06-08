package group

import (
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	U "github.com/sagernet/sing-box/common/urltest"
	N "github.com/sagernet/sing/common/network"
	"github.com/stretchr/testify/require"
)

func TestLoadBalanceSelectPreMatchOutboundWithMetadata(t *testing.T) {
	selectedOutbound := new(preMatchTestOutbound)
	metadata := &adapter.InboundContext{Network: N.NetworkUDP}
	var receivedMetadata *adapter.InboundContext
	var receivedTouch bool
	loadBalance := &LoadBalance{
		group: &LoadBalanceGroup{
			strategyFn: func(metadata *adapter.InboundContext, touch bool, matcher outboundMatcher) adapter.Outbound {
				receivedMetadata = metadata
				receivedTouch = touch
				if matcher != nil && !matcher(selectedOutbound) {
					return nil
				}
				return selectedOutbound
			},
		},
	}

	outbound, action := loadBalance.SelectPreMatchOutbound(metadata, selectPreMatchFlow)
	require.Same(t, selectedOutbound, outbound)
	require.Equal(t, adapter.PreMatchFlow, action)
	require.Same(t, metadata, receivedMetadata)
	require.True(t, receivedTouch)
}

func TestLoadBalancePreMatchDoesNotConsumeIneligibleRoundRobinSelection(t *testing.T) {
	firstOutbound := &preMatchTestOutbound{tag: "first"}
	secondOutbound := &preMatchTestOutbound{tag: "second"}
	history := U.NewHistoryStorage()
	history.StoreURLTestHistory(firstOutbound.Tag(), new(adapter.URLTestHistory))
	history.StoreURLTestHistory(secondOutbound.Tag(), new(adapter.URLTestHistory))
	loadBalanceGroup := &LoadBalanceGroup{
		outbounds: []adapter.Outbound{firstOutbound, secondOutbound},
		history:   history,
	}
	loadBalanceGroup.strategyFn = strategyRoundRobin(loadBalanceGroup, "")
	loadBalance := &LoadBalance{group: loadBalanceGroup}
	metadata := new(adapter.InboundContext)

	selectedOutbound, action := loadBalance.SelectPreMatchOutbound(metadata, func(adapter.Outbound) (adapter.Outbound, adapter.PreMatchAction) {
		return nil, adapter.PreMatchContinue
	})
	require.Nil(t, selectedOutbound)
	require.Equal(t, adapter.PreMatchContinue, action)
	require.Same(t, firstOutbound, loadBalanceGroup.Unwrap(metadata, true))
}

func TestLoadBalancePreMatchAdvancesAcceptedRoundRobinSelection(t *testing.T) {
	firstOutbound := &preMatchTestOutbound{tag: "first"}
	secondOutbound := &preMatchTestOutbound{tag: "second"}
	history := U.NewHistoryStorage()
	history.StoreURLTestHistory(firstOutbound.Tag(), new(adapter.URLTestHistory))
	history.StoreURLTestHistory(secondOutbound.Tag(), new(adapter.URLTestHistory))
	loadBalanceGroup := &LoadBalanceGroup{
		outbounds: []adapter.Outbound{firstOutbound, secondOutbound},
		history:   history,
	}
	loadBalanceGroup.strategyFn = strategyRoundRobin(loadBalanceGroup, "")
	loadBalance := &LoadBalance{group: loadBalanceGroup}
	metadata := new(adapter.InboundContext)

	selectedOutbound, action := loadBalance.SelectPreMatchOutbound(metadata, selectPreMatchFlow)
	require.Same(t, firstOutbound, selectedOutbound)
	require.Equal(t, adapter.PreMatchFlow, action)
	selectedOutbound, action = loadBalance.SelectPreMatchOutbound(metadata, selectPreMatchFlow)
	require.Same(t, secondOutbound, selectedOutbound)
	require.Equal(t, adapter.PreMatchFlow, action)
}

func TestLoadBalanceStickyPreMatchReusesIneligibleSelectionForL4(t *testing.T) {
	nonL3Outbound := &preMatchTestOutbound{tag: "non-l3"}
	l3Outbound := &preMatchTestOutbound{tag: "l3"}
	history := U.NewHistoryStorage()
	history.StoreURLTestHistory(nonL3Outbound.Tag(), new(adapter.URLTestHistory))
	history.StoreURLTestHistory(l3Outbound.Tag(), new(adapter.URLTestHistory))
	loadBalanceGroup := &LoadBalanceGroup{
		outbounds: []adapter.Outbound{nonL3Outbound, l3Outbound},
		history:   history,
		ttl:       time.Minute,
	}
	var selectIndexCount int
	loadBalanceGroup.strategyFn = strategyStickySessionsWithIndex(loadBalanceGroup, func(_ uint64, length int) int {
		index := selectIndexCount % length
		selectIndexCount++
		return index
	})
	loadBalance := &LoadBalance{group: loadBalanceGroup}
	metadata := new(adapter.InboundContext)
	var preMatchCandidate adapter.Outbound

	selectedOutbound, action := loadBalance.SelectPreMatchOutbound(metadata, func(outbound adapter.Outbound) (adapter.Outbound, adapter.PreMatchAction) {
		preMatchCandidate = outbound
		if outbound == nonL3Outbound {
			return nil, adapter.PreMatchContinue
		}
		return outbound, adapter.PreMatchFlow
	})
	require.Nil(t, selectedOutbound)
	require.Equal(t, adapter.PreMatchContinue, action)
	require.Same(t, nonL3Outbound, preMatchCandidate)
	require.Same(t, nonL3Outbound, loadBalanceGroup.Unwrap(metadata, true))
	require.Equal(t, 1, selectIndexCount)
}
