package group

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	adapterOutbound "github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

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
