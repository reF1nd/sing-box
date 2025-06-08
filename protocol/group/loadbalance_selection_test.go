package group

import (
	"context"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	adapterOutbound "github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

func TestLoadBalanceConnectionSelectionReceivesMetadata(t *testing.T) {
	leaf := &preMatchTestOutbound{tag: "leaf"}
	metadata := &adapter.InboundContext{
		Network: N.NetworkUDP, Source: M.ParseSocksaddr("192.0.2.1:1234"),
		Destination: M.ParseSocksaddr("www.example.com:443"), SniffHost: "example.com",
	}
	calls := 0
	balance := &LoadBalance{group: &LoadBalanceGroup{strategyFn: func(received *adapter.InboundContext, touch bool, matcher outboundMatcher) adapter.Outbound {
		calls++
		require.Same(t, metadata, received)
		require.True(t, touch)
		require.Nil(t, matcher)
		return leaf
	}}}
	require.Nil(t, balance.Selected(N.NetworkTCP))
	require.Nil(t, balance.Selected(N.NetworkUDP))
	require.Zero(t, calls)
	require.Same(t, leaf, balance.SelectConnection(metadata))
	require.Equal(t, 1, calls)
}

func TestLoadBalanceNetworkSpecificHealth(t *testing.T) {
	healthyTCP := &preMatchTestOutbound{tag: "tcp"}
	unhealthyUDP := &preMatchTestOutbound{tag: "udp"}
	alternative := &preMatchTestOutbound{tag: "alternative"}
	history := urltest.NewHistoryStorage()
	history.StoreURLTestHistory(healthyTCP.Tag(), &adapter.URLTestHistory{Delay: 10})
	history.StoreURLTestHistory(alternative.Tag(), &adapter.URLTestHistory{Delay: 20})
	nested := &URLTest{Adapter: adapterOutbound.NewAdapter(C.TypeURLTest, "nested", nil, nil), group: new(URLTestGroup)}
	nested.group.selectedOutboundTCP.Store(healthyTCP)
	nested.group.selectedOutboundUDP.Store(unhealthyUDP)
	group := &LoadBalanceGroup{history: history, outbounds: []adapter.Outbound{nested, alternative}}
	group.strategyFn = strategyRoundRobin(group, "")
	require.Same(t, alternative, group.Unwrap(&adapter.InboundContext{Network: N.NetworkUDP}, true))
	require.Same(t, nested, group.Unwrap(&adapter.InboundContext{Network: N.NetworkTCP}, true))
	_, incorrectlyClassified := any(nested).(adapter.LoadBalanceGroup)
	require.False(t, incorrectlyClassified)
}

func TestLoadBalanceEmptyCandidates(t *testing.T) {
	for _, strategy := range []strategyFn{
		strategyRoundRobin(new(LoadBalanceGroup), ""),
		strategyConsistentHashing(new(LoadBalanceGroup), ""),
		strategyStickySessions(new(LoadBalanceGroup), ""),
	} {
		require.Nil(t, strategy(new(adapter.InboundContext), true, nil))
	}
}

func TestLoadBalanceDialMetadataIsIndependent(t *testing.T) {
	original := &adapter.InboundContext{Source: M.ParseSocksaddr("192.0.2.1:1234"), Destination: M.ParseSocksaddr("original.example:53"), Network: N.NetworkTCP}
	destination := M.ParseSocksaddr("dns.example:443")
	copy := loadBalanceDialMetadata(adapter.WithContext(context.Background(), original), N.NetworkUDP, destination)
	require.Equal(t, original.Source, copy.Source)
	require.Equal(t, destination, copy.Destination)
	require.Equal(t, N.NetworkUDP, copy.Network)
	require.Equal(t, "original.example", original.Destination.Fqdn)
	require.Equal(t, N.NetworkTCP, original.Network)
	empty := loadBalanceDialMetadata(context.Background(), N.NetworkTCP, destination)
	require.Equal(t, "dns.example", getKey(&empty))
}

func TestLoadBalanceCloseWithoutTicker(t *testing.T) {
	group := &LoadBalanceGroup{close: make(chan struct{})}
	group.started.Store(true)
	require.NoError(t, group.Close())
	require.NoError(t, group.Close())
	group.Touch()
	require.Nil(t, group.ticker)
	select {
	case <-group.close:
	default:
		t.Fatal("idle group did not close its loop channel")
	}
}

type networkTestOutbound struct {
	adapter.Outbound
	tag      string
	networks []string
}

func (o *networkTestOutbound) Tag() string       { return o.tag }
func (o *networkTestOutbound) Network() []string { return o.networks }

func TestLoadBalanceFiltersMembersByNetworkCapability(t *testing.T) {
	tcpOnly := &networkTestOutbound{tag: "ssh", networks: []string{N.NetworkTCP}}
	dual := &networkTestOutbound{tag: "direct", networks: []string{N.NetworkTCP, N.NetworkUDP}}

	for _, withHistory := range []bool{true, false} {
		name := "with_history"
		if !withHistory {
			name = "fallback_without_history"
		}
		t.Run(name, func(t *testing.T) {
			history := urltest.NewHistoryStorage()
			if withHistory {
				history.StoreURLTestHistory(tcpOnly.Tag(), &adapter.URLTestHistory{Delay: 10})
				history.StoreURLTestHistory(dual.Tag(), &adapter.URLTestHistory{Delay: 20})
			}
			for _, tc := range []struct {
				name string
				make func(*LoadBalanceGroup) strategyFn
			}{
				{"round-robin", func(g *LoadBalanceGroup) strategyFn { return strategyRoundRobin(g, "") }},
				{"consistent-hashing", func(g *LoadBalanceGroup) strategyFn { return strategyConsistentHashing(g, "") }},
				{"sticky-sessions", func(g *LoadBalanceGroup) strategyFn { return strategyStickySessions(g, "") }},
			} {
				t.Run(tc.name, func(t *testing.T) {
					group := &LoadBalanceGroup{
						history:   history,
						outbounds: []adapter.Outbound{tcpOnly, dual},
						ttl:       time.Minute,
					}
					group.strategyFn = tc.make(group)
					for range 4 {
						chosen := group.Unwrap(&adapter.InboundContext{
							Network:     N.NetworkUDP,
							Source:      M.ParseSocksaddr("192.0.2.1:1000"),
							Destination: M.ParseSocksaddr("example.com:443"),
						}, true)
						require.Same(t, dual, chosen)
					}
				})
			}
		})
	}
}

func TestLoadBalanceStickySessionsPreservesIdentityAcrossReorder(t *testing.T) {
	a := &preMatchTestOutbound{tag: "A"}
	b := &preMatchTestOutbound{tag: "B"}
	history := urltest.NewHistoryStorage()
	history.StoreURLTestHistory(a.Tag(), &adapter.URLTestHistory{Delay: 10})
	history.StoreURLTestHistory(b.Tag(), &adapter.URLTestHistory{Delay: 20})
	group := &LoadBalanceGroup{
		history:   history,
		outbounds: []adapter.Outbound{a, b},
		ttl:       time.Minute,
	}
	group.strategyFn = strategyStickySessionsWithIndex(group, func(_ uint64, _ int) int { return 0 })
	meta := &adapter.InboundContext{
		Network:     N.NetworkTCP,
		Source:      M.ParseSocksaddr("192.0.2.1:1000"),
		Destination: M.ParseSocksaddr("example.com:443"),
	}
	require.Same(t, a, group.Unwrap(meta, true))
	// Reorder [A, B] -> [B, A]; sticky session must remain pinned to A.
	group.storeOutbounds([]adapter.Outbound{b, a})
	require.Same(t, a, group.Unwrap(meta, true))
}

func TestLoadBalanceStickySessionsScansAllMembersForHealthyFallback(t *testing.T) {
	dead1 := &preMatchTestOutbound{tag: "dead-1"}
	dead2 := &preMatchTestOutbound{tag: "dead-2"}
	alive := &preMatchTestOutbound{tag: "alive"}
	history := urltest.NewHistoryStorage()
	history.StoreURLTestHistory(alive.Tag(), &adapter.URLTestHistory{Delay: 15})
	group := &LoadBalanceGroup{
		history:   history,
		outbounds: []adapter.Outbound{dead1, dead2, alive},
		ttl:       time.Minute,
	}
	// Force all random probes to land on index 0 (dead1); full-list scan must still pick alive.
	group.strategyFn = strategyStickySessionsWithIndex(group, func(_ uint64, _ int) int { return 0 })
	meta := &adapter.InboundContext{
		Network:     N.NetworkTCP,
		Source:      M.ParseSocksaddr("192.0.2.1:1000"),
		Destination: M.ParseSocksaddr("example.com:443"),
	}
	require.Same(t, alive, group.Unwrap(meta, true))
	// Subsequent hit stays cached on alive without needing probes.
	require.Same(t, alive, group.Unwrap(meta, true))
}

func TestLoadBalanceStickySessionsIncompatibleNetworkDoesNotOverwriteBinding(t *testing.T) {
	a := &networkTestOutbound{tag: "A", networks: []string{N.NetworkTCP}}
	b := &networkTestOutbound{tag: "B", networks: []string{N.NetworkTCP}}
	history := urltest.NewHistoryStorage()
	history.StoreURLTestHistory(a.Tag(), &adapter.URLTestHistory{Delay: 10})
	history.StoreURLTestHistory(b.Tag(), &adapter.URLTestHistory{Delay: 20})
	group := &LoadBalanceGroup{
		history:   history,
		outbounds: []adapter.Outbound{a, b},
		ttl:       time.Minute,
	}
	group.strategyFn = strategyStickySessionsWithIndex(group, func(_ uint64, _ int) int { return 0 })
	tcpMeta := &adapter.InboundContext{
		Network:     N.NetworkTCP,
		Source:      M.ParseSocksaddr("192.0.2.1:1000"),
		Destination: M.ParseSocksaddr("example.com:443"),
	}
	udpMeta := &adapter.InboundContext{
		Network:     N.NetworkUDP,
		Source:      M.ParseSocksaddr("192.0.2.1:1000"),
		Destination: M.ParseSocksaddr("example.com:443"),
	}
	require.Same(t, a, group.Unwrap(tcpMeta, true))
	require.Nil(t, group.Unwrap(udpMeta, true))
	// UDP rejection must not overwrite the existing TCP sticky binding to A.
	require.Same(t, a, group.Unwrap(tcpMeta, true))
}

func TestLoadBalanceStickySessionsUntestedReorderPreservesIdentity(t *testing.T) {
	a := &preMatchTestOutbound{tag: "A"}
	b := &preMatchTestOutbound{tag: "B"}
	group := &LoadBalanceGroup{
		history:   urltest.NewHistoryStorage(),
		outbounds: []adapter.Outbound{a, b},
		ttl:       time.Minute,
	}
	group.strategyFn = strategyStickySessionsWithIndex(group, func(_ uint64, _ int) int { return 0 })
	meta := &adapter.InboundContext{
		Network:     N.NetworkTCP,
		Source:      M.ParseSocksaddr("192.0.2.1:1000"),
		Destination: M.ParseSocksaddr("example.com:443"),
	}
	first := group.Unwrap(meta, true)
	require.NotNil(t, first)
	// Reverse member order with no test history; sticky session must keep first member.
	group.storeOutbounds([]adapter.Outbound{b, a})
	require.Same(t, first, group.Unwrap(meta, true))
}
