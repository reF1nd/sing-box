package route

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/expiringmap"
	"github.com/sagernet/sing-box/common/interrupt"
	"github.com/sagernet/sing-box/common/trafficcontrol"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/group"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

func newRouteLoadBalance(t *testing.T, strategy string) *group.LoadBalance {
	t.Helper()
	first := &testFlowOutbound{tag: "first", outboundType: C.TypeDirect}
	second := &testFlowOutbound{tag: "second", outboundType: C.TypeDirect}
	manager := &testL3OutboundManager{outbounds: map[string]adapter.Outbound{"first": first, "second": second}}
	history := urltest.NewHistoryStorage()
	history.StoreURLTestHistory("first", &adapter.URLTestHistory{Delay: 10})
	history.StoreURLTestHistory("second", &adapter.URLTestHistory{Delay: 20})
	ctx := service.ContextWith[adapter.OutboundManager](context.Background(), manager)
	ctx = service.ContextWithPtr(ctx, history)
	outbound, err := group.NewLoadBalance(ctx, nil, logger.NOP(), "balance", option.LoadBalanceOutboundOptions{
		GroupCommonOption: option.GroupCommonOption{Outbounds: []string{"first", "second"}}, Strategy: strategy,
	})
	require.NoError(t, err)
	balance := outbound.(*group.LoadBalance)
	require.NoError(t, balance.Start())
	t.Cleanup(func() { require.NoError(t, balance.Close()) })
	return balance
}

func TestResolveLoadBalanceChainAndTrackerSnapshot(t *testing.T) {
	for _, network := range []string{N.NetworkTCP, N.NetworkUDP} {
		t.Run(network, func(t *testing.T) {
			balance := newRouteLoadBalance(t, group.StrategyRoundRobin)
			outer := &testOutboundGroup{Outbound: &testFlowOutbound{tag: "outer"}, selected: balance, interrupts: &quicCloseGroup{group: interrupt.NewGroup()}}
			metadata := quicCloseMetadata()
			metadata.Network = network
			require.Nil(t, balance.Selected(network))
			require.Equal(t, "balance", group.RealTag(outer, network))
			chain, err := resolveOutbound(outer, network, &metadata)
			require.NoError(t, err)
			require.Len(t, chain, 3)
			require.Equal(t, "first", chain[2].Tag())
			metadata.OutboundChain = chain
			traffic := trafficcontrol.NewManager()
			require.NoError(t, traffic.Start(adapter.StartStateInitialize))
			defer traffic.Close()
			conn, peer := net.Pipe()
			defer peer.Close()
			tracked := traffic.RoutedConnection(context.Background(), conn, metadata, nil, outer)
			defer tracked.Close()
			snapshot := traffic.Connections()[0]
			require.Equal(t, []string{"first", "balance", "outer"}, snapshot.Chain)
			require.Equal(t, "first", snapshot.Outbound)
			nextChain, err := resolveOutbound(outer, network, &metadata)
			require.NoError(t, err)
			require.Equal(t, "second", nextChain[2].Tag())
			require.Equal(t, []string{"first", "balance", "outer"}, snapshot.Chain)

			router := &Router{quicSniffCache: expiringmap.New[quicSniffCacheKey, string](time.Minute)}
			defer router.quicSniffCache.Close()
			packet := &quicClosePacketConn{}
			completions := 0
			packet.onClose = registerInterrupt(chain, packet, router.wrapQUICSniffIdleCache(metadata, func(error) { completions++ }))
			outer.interrupts.group.Interrupt(true)
			outer.interrupts.group.Interrupt(true)
			require.Equal(t, 1, packet.closes)
			require.Equal(t, 1, completions)
			host, found := router.lookupQUICSniff(metadata.Source, metadata.Destination)
			require.True(t, found)
			require.Equal(t, metadata.SniffHost, host)
		})
	}
}

func TestResolveLoadBalanceStableStrategies(t *testing.T) {
	for _, strategy := range []string{group.StrategyConsistentHashing, group.StrategyStickySessions} {
		t.Run(strategy, func(t *testing.T) {
			balance := newRouteLoadBalance(t, strategy)
			metadata := adapter.InboundContext{Source: M.ParseSocksaddr("192.0.2.1:10000"), Destination: M.ParseSocksaddr("www.example.com:443")}
			first, err := resolveOutbound(balance, N.NetworkTCP, &metadata)
			require.NoError(t, err)
			for range 10 {
				next, err := resolveOutbound(balance, N.NetworkTCP, &metadata)
				require.NoError(t, err)
				require.Same(t, first[1], next[1])
			}
			require.Empty(t, metadata.Network, "selection must not change the caller's metadata")
		})
	}
}

type failureListenerGroup struct {
	adapter.Outbound
	calls int
}

func (g *failureListenerGroup) OnConnectionFailure(context.Context) { g.calls++ }

type failureDialer struct{ N.Dialer }

func (failureDialer) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, errors.New("dial failed")
}

func (failureDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("listen failed")
}

func TestResolvedChainNotifiesDialFailure(t *testing.T) {
	listener := new(failureListenerGroup)
	metadata := adapter.InboundContext{Destination: M.ParseSocksaddr("example.com:443"), OutboundChain: []adapter.Outbound{listener}}
	manager := NewConnectionManager(logger.NOP())
	conn, peer := net.Pipe()
	defer peer.Close()
	manager.NewConnection(context.Background(), failureDialer{}, conn, metadata, nil)
	require.Equal(t, 1, listener.calls)
	manager.NewPacketConnection(context.Background(), failureDialer{}, &quicClosePacketConn{}, metadata, nil)
	require.Equal(t, 2, listener.calls)
	metadata.UDPConnect = true
	manager.NewPacketConnection(context.Background(), failureDialer{}, &quicClosePacketConn{}, metadata, nil)
	require.Equal(t, 3, listener.calls)
}
