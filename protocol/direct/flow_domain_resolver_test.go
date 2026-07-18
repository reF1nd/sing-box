package direct

import (
	"context"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

func TestFlowDomainResolveOptionsDuringFirstDial(t *testing.T) {
	transport := new(testFlowDNSTransport)
	ctx := service.ContextWith[adapter.DNSTransportManager](context.Background(), &testFlowDNSTransportManager{transport: transport})
	rawOutbound, err := NewOutbound(ctx, nil, log.NewNOPFactory().NewLogger("direct"), "direct", option.DirectOutboundOptions{
		DialerOptions: option.DialerOptions{AbstractDialerOptions: option.AbstractDialerOptions{
			DomainResolver: &option.DomainResolveOptions{
				Server:       "resolver",
				Strategy:     option.DomainStrategy(C.DomainStrategyIPv4Only),
				Timeout:      badoption.Duration(3 * time.Second),
				DisableCache: true,
			},
		}},
	})
	require.NoError(t, err)
	outbound := rawOutbound.(*Outbound)
	t.Cleanup(func() { require.NoError(t, outbound.Close()) })
	expected := adapter.DNSQueryOptions{
		Transport:    transport,
		Strategy:     C.DomainStrategyIPv4Only,
		Timeout:      3 * time.Second,
		DisableCache: true,
	}
	require.Equal(t, expected, outbound.FlowDomainResolveOptions())
	// Exercise an L3 resolver read concurrently with the first L4 dial, which
	// initializes the resolve dialer. Cancellation avoids external network I/O.
	dialCtx, cancel := context.WithCancel(ctx)
	cancel()
	start := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		<-start
		conn, dialErr := outbound.DialContext(dialCtx, N.NetworkTCP, M.ParseSocksaddr("127.0.0.1:1"))
		if conn != nil {
			conn.Close()
		}
		result <- dialErr
	}()
	close(start)
	for range 1000 {
		require.Equal(t, expected, outbound.FlowDomainResolveOptions())
	}
	require.ErrorIs(t, <-result, context.Canceled)
}

type testFlowDNSTransport struct{ adapter.DNSTransport }

type testFlowDNSTransportManager struct {
	adapter.DNSTransportManager
	transport adapter.DNSTransport
}

func (m *testFlowDNSTransportManager) Transport(tag string) (adapter.DNSTransport, bool) {
	return m.transport, tag == "resolver"
}
