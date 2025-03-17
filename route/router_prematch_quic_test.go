package route

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/expiringmap"
	"github.com/sagernet/sing-box/common/interrupt"
	"github.com/sagernet/sing-box/common/sniff"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	R "github.com/sagernet/sing-box/route/rule"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

func TestPreMatchQUICCacheDomainRule(t *testing.T) {
	for _, cached := range []bool{false, true} {
		router, metadata := newPreMatchQUICRouter(t, time.Minute)
		sniffAction := &R.RuleActionSniff{}
		if cached {
			router.cacheQUICSniff(metadata.Source, metadata.Destination, "example.com")
		} else {
			// The QUIC parser has its own packet fixtures; exercise the successful
			// sniff result entering the pre-match cache and rule pipeline here.
			sniffAction.PacketSniffers = []sniff.PacketSniffer{func(_ context.Context, metadata *adapter.InboundContext, _ []byte) error {
				metadata.Protocol = C.ProtocolQUIC
				metadata.SniffHost = "example.com"
				return nil
			}}
		}
		rejectRule, err := R.NewDefaultRule(context.Background(), logger.NOP(), option.DefaultRule{
			RawDefaultRule: option.RawDefaultRule{Domain: []string{"example.com"}},
			RuleAction: option.RuleAction{
				Action:        C.RuleActionTypeReject,
				RejectOptions: option.RejectActionOptions{Method: C.RuleActionRejectMethodDrop},
			},
		})
		require.NoError(t, err)
		router.rules = []adapter.Rule{
			&preMatchQUICRule{action: sniffAction},
			rejectRule,
			&preMatchQUICRule{action: &R.RuleActionBypass{}},
		}
		result := router.PreMatch(metadata, quicShortPacket())
		require.Equal(t, adapter.PreMatchDrop, result.Action)
		host, loaded := router.lookupQUICSniff(metadata.Source, metadata.Destination)
		require.True(t, loaded)
		require.Equal(t, "example.com", host)
	}
}

func TestPreMatchQUICFlowCacheClose(t *testing.T) {
	for _, testCase := range []struct {
		name        string
		interrupt   bool
		newerHost   bool
		closedCache bool
	}{
		{name: "timeout"},
		{name: "group interrupt", interrupt: true},
		{name: "newer host", newerHost: true},
		{name: "closed cache", closedCache: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			router, metadata := newPreMatchQUICRouter(t, 30*time.Millisecond)
			router.cacheQUICSniff(metadata.Source, metadata.Destination, "example.com")
			group := &preMatchQUICGroup{
				quicCloseGroup: &quicCloseGroup{group: interrupt.NewGroup()},
				selected:       &preMatchQUICOutbound{},
			}
			router.outbound = &preMatchQUICOutbounds{outbound: group}
			router.rules = []adapter.Rule{
				&preMatchQUICRule{action: &R.RuleActionSniff{}},
				&preMatchQUICRule{action: &R.RuleActionRoute{RuleActionRouteOptions: R.RuleActionRouteOptions{
					OverrideAddress: M.ParseSocksaddr("192.0.2.1:0"),
				}}},
			}
			result := router.PreMatch(metadata, quicShortPacket())
			require.Equal(t, adapter.PreMatchFlow, result.Action)
			require.Equal(t, netip.MustParseAddrPort("192.0.2.1:443"), result.Destination)
			require.NotNil(t, result.NewTracker)
			tracker := result.NewTracker()
			handle := &preMatchQUICHandle{tracker: tracker}
			tracker.AttachFlow(handle)
			require.Eventually(t, func() bool { return router.quicSniffCache.Len() == 0 }, time.Second, time.Millisecond)
			if testCase.newerHost {
				router.cacheQUICSniff(metadata.Source, metadata.Destination, "new.example")
			}
			if testCase.closedCache {
				router.quicSniffCache.Close()
			}
			if testCase.interrupt {
				group.group.Interrupt(true)
				require.Equal(t, 1, handle.closes)
			} else {
				tracker.CloseFlow(tun.FlowCloseTimeout)
			}
			require.Equal(t, 1, group.removals)
			group.group.Interrupt(true)
			host, loaded := router.lookupQUICSniff(metadata.Source, metadata.Destination)
			require.Equal(t, !testCase.closedCache, loaded)
			if testCase.newerHost {
				require.Equal(t, "new.example", host)
			} else if loaded {
				require.Equal(t, "example.com", host)
			}
			_, wrongKey := router.lookupQUICSniff(metadata.Source, M.ParseSocksaddr("192.0.2.1:443"))
			require.False(t, wrongKey)
			// A repeated completion must not resurrect an expired cache entry.
			require.Eventually(t, func() bool { return router.quicSniffCache.Len() == 0 }, time.Second, time.Millisecond)
			tracker.CloseFlow(tun.FlowCloseFinished)
			require.Zero(t, router.quicSniffCache.Len())
		})
	}
}

func newPreMatchQUICRouter(t *testing.T, lifetime time.Duration) (*Router, adapter.InboundContext) {
	t.Helper()
	router := &Router{
		ctx:            context.Background(),
		logger:         logger.NOP(),
		dnsTransport:   &preMatchQUICDNSManager{},
		quicSniffCache: expiringmap.New[quicSniffCacheKey, string](lifetime),
	}
	t.Cleanup(router.quicSniffCache.Close)
	metadata := quicCloseMetadata()
	metadata.Network = N.NetworkUDP
	metadata.Protocol = ""
	metadata.SniffHost = ""
	metadata.Domain = "reverse.example"
	return router, metadata
}

func quicShortPacket() []byte {
	return append([]byte{0x40}, make([]byte, 20)...)
}

type preMatchQUICDNSManager struct{ adapter.DNSTransportManager }

func (*preMatchQUICDNSManager) FakeIP() adapter.FakeIPTransport { return nil }

type preMatchQUICRule struct {
	adapter.Rule
	action adapter.RuleAction
}

func (r *preMatchQUICRule) Action() adapter.RuleAction { return r.action }

func (*preMatchQUICRule) String() string { return "" }

func (*preMatchQUICRule) Match(*adapter.InboundContext) bool { return true }

type preMatchQUICOutbounds struct {
	adapter.OutboundManager
	outbound adapter.Outbound
}

func (m *preMatchQUICOutbounds) Default() adapter.Outbound { return m.outbound }

type preMatchQUICOutbound struct{ adapter.FlowOutbound }

func (*preMatchQUICOutbound) Type() string { return "test" }

func (*preMatchQUICOutbound) Tag() string { return "test" }

func (*preMatchQUICOutbound) Network() []string { return []string{N.NetworkUDP} }

func (*preMatchQUICOutbound) PreMatchFlow(string, netip.Addr) adapter.PreMatchAction {
	return adapter.PreMatchFlow
}

type preMatchQUICGroup struct {
	*quicCloseGroup
	selected adapter.Outbound
}

func (g *preMatchQUICGroup) Selected(string) adapter.Outbound { return g.selected }

type preMatchQUICHandle struct {
	tracker tun.FlowTracker
	closes  int
}

func (h *preMatchQUICHandle) CloseFlow() {
	h.closes++
	h.tracker.CloseFlow(tun.FlowCloseReset)
}
