package route

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

func TestRoutePacketConnectionReturnsOnRouteFailure(t *testing.T) {
	router := &Router{
		ctx:          context.Background(),
		logger:       logger.NOP(),
		dnsTransport: &legacyRouteDNSTransportManager{},
		outbound:     &legacyRouteOutboundManager{defaultOutbound: &legacyRouteTCPOutbound{}},
	}
	conn := &legacyRoutePacketConn{}
	done := make(chan error, 1)
	go func() {
		done <- router.RoutePacketConnection(context.Background(), conn, adapter.InboundContext{
			Destination: M.ParseSocksaddr("example.com:443"),
			Domain:      "example.com",
		})
	}()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("RoutePacketConnection blocked after route failure")
	}
	require.True(t, conn.closed.Load())
}

type legacyRouteDNSTransportManager struct{ adapter.DNSTransportManager }

func (*legacyRouteDNSTransportManager) FakeIP() adapter.FakeIPTransport { return nil }

type legacyRouteOutboundManager struct {
	adapter.OutboundManager
	defaultOutbound adapter.Outbound
}

func (m *legacyRouteOutboundManager) Default() adapter.Outbound { return m.defaultOutbound }

type legacyRouteTCPOutbound struct{ adapter.Outbound }

func (*legacyRouteTCPOutbound) Tag() string { return "tcp-only" }

func (*legacyRouteTCPOutbound) Network() []string { return []string{N.NetworkTCP} }

type legacyRoutePacketConn struct {
	N.PacketConn
	closed atomic.Bool
}

func (c *legacyRoutePacketConn) Close() error {
	c.closed.Store(true)
	return nil
}
