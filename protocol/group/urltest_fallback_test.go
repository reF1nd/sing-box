package group

import (
	"context"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

func TestFallbackChoosesFastestWhenAllExceedThreshold(t *testing.T) {
	slow := &preMatchTestOutbound{tag: "slow"}
	fast := &preMatchTestOutbound{tag: "fast"}
	history := urltest.NewHistoryStorage()
	history.StoreURLTestHistory(slow.Tag(), &adapter.URLTestHistory{Delay: 500})
	history.StoreURLTestHistory(fast.Tag(), &adapter.URLTestHistory{Delay: 200})
	group := &URLTestGroup{
		outbounds: []adapter.Outbound{slow, fast}, history: history,
		fallback: URLTestFallback{enabled: true, maxDelay: 100},
	}
	group.selectedOutboundTCP.Store(slow)
	group.selectedOutboundUDP.Store(slow)
	for _, network := range []string{N.NetworkTCP, N.NetworkUDP} {
		selected, available := group.Select(network)
		require.True(t, available)
		require.Same(t, fast, selected)
	}
}

func TestFallbackLongMaximumDelayDoesNotWrap(t *testing.T) {
	instance, err := NewURLTest(context.Background(), nil, nil, "test", option.URLTestOutboundOptions{
		Fallback: option.URLTestFallbackOptions{Enabled: true, MaxDelay: badoption.Duration(70 * time.Second)},
	})
	require.NoError(t, err)
	first := &preMatchTestOutbound{tag: "first"}
	second := &preMatchTestOutbound{tag: "second"}
	history := urltest.NewHistoryStorage()
	history.StoreURLTestHistory(first.Tag(), &adapter.URLTestHistory{Delay: 5000})
	history.StoreURLTestHistory(second.Tag(), &adapter.URLTestHistory{Delay: 2000})
	group := &URLTestGroup{
		outbounds: []adapter.Outbound{first, second}, history: history,
		fallback: instance.(*URLTest).fallback,
	}
	selected, available := group.Select(N.NetworkTCP)
	require.True(t, available)
	require.Same(t, first, selected)
}
