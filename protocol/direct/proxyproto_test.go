package direct

import (
	"context"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

type emptyTestNetworkManager struct {
	adapter.NetworkManager
}

func (emptyTestNetworkManager) DefaultOptions() adapter.NetworkOptions {
	return adapter.NetworkOptions{}
}

func (emptyTestNetworkManager) AutoDetectInterface() bool                          { return false }
func (emptyTestNetworkManager) AutoRedirectOutputMark() uint32                     { return 0 }
func (emptyTestNetworkManager) AutoRedirectOutputMarkFunc() control.Func           { return nil }
func (emptyTestNetworkManager) InterfaceFinder() control.InterfaceFinder           { return nil }
func (emptyTestNetworkManager) InterfaceMonitor() tun.DefaultInterfaceMonitor      { return nil }
func (emptyTestNetworkManager) DefaultNetworkInterface() *adapter.NetworkInterface { return nil }

type emptyTestDNSTransportManager struct {
	adapter.DNSTransportManager
}

func (emptyTestDNSTransportManager) Transports() []adapter.DNSTransport { return nil }
func (emptyTestDNSTransportManager) Default() adapter.DNSTransport      { return nil }

type proxyProtoTestConn struct {
	net.Conn
	closed atomic.Bool
}

func (c *proxyProtoTestConn) Close() error {
	c.closed.Store(true)
	return c.Conn.Close()
}

type proxyProtoTestDialer struct {
	parallelResolveDialer
	conn net.Conn
}

func (d *proxyProtoTestDialer) DialContext(_ context.Context, _ string, _ M.Socksaddr) (net.Conn, error) {
	return d.conn, nil
}

func (d *proxyProtoTestDialer) DialParallelNetwork(_ context.Context, _ string, _ M.Socksaddr, _ []netip.Addr, _ *C.NetworkStrategy, _ []C.InterfaceType, _ []C.InterfaceType, _ time.Duration) (net.Conn, error) {
	return d.conn, nil
}

func TestDirectProxyProtocolRejectsFQDNOriginDestination(t *testing.T) {
	for _, entry := range []string{"DialContext", "DialParallel", "DialParallelNetwork"} {
		for _, version := range []uint8{1, 2} {
			t.Run(entry+"_v"+string('0'+version), func(t *testing.T) {
				client, server := net.Pipe()
				defer server.Close()
				tracked := &proxyProtoTestConn{Conn: client}
				o := &Outbound{
					Adapter:    outbound.NewAdapter(C.TypeDirect, "direct", []string{N.NetworkTCP, N.NetworkUDP}, nil),
					logger:     logger.NOP(),
					dialer:     &proxyProtoTestDialer{conn: tracked},
					proxyProto: version,
				}
				ctx := adapter.WithContext(context.Background(), &adapter.InboundContext{
					Source:      M.ParseSocksaddr("192.0.2.10:12345"),
					Destination: M.ParseSocksaddr("example.com:443"),
				})
				var (
					conn net.Conn
					err  error
				)
				switch entry {
				case "DialContext":
					conn, err = o.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr("example.com:443"))
				case "DialParallel":
					conn, err = o.DialParallel(ctx, N.NetworkTCP, M.ParseSocksaddr("example.com:443"), []netip.Addr{netip.MustParseAddr("198.51.100.20")})
				case "DialParallelNetwork":
					conn, err = o.DialParallelNetwork(ctx, N.NetworkTCP, M.ParseSocksaddr("example.com:443"), []netip.Addr{netip.MustParseAddr("198.51.100.20")}, nil, nil, nil, 0)
				}
				require.Error(t, err)
				require.Nil(t, conn)
				require.True(t, tracked.closed.Load(), "connection must be closed when PROXY header cannot encode destination")
			})
		}
	}
}

func TestDirectProxyProtocolSkipsConnectedUDP(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	o := &Outbound{
		Adapter:    outbound.NewAdapter(C.TypeDirect, "direct", []string{N.NetworkTCP, N.NetworkUDP}, nil),
		logger:     logger.NOP(),
		dialer:     &proxyProtoTestDialer{conn: client},
		proxyProto: 1,
	}
	readDone := make(chan string, 1)
	go func() {
		buf := make([]byte, 64)
		n, _ := server.Read(buf)
		readDone <- string(buf[:n])
		_, _ = io.Copy(io.Discard, server)
	}()
	ctx := adapter.WithContext(context.Background(), &adapter.InboundContext{
		Source:      M.ParseSocksaddr("192.0.2.10:12345"),
		Destination: M.ParseSocksaddr("198.51.100.20:53"),
	})
	conn, err := o.DialParallelNetwork(ctx, N.NetworkUDP, M.ParseSocksaddr("198.51.100.20:53"), []netip.Addr{netip.MustParseAddr("198.51.100.20")}, nil, nil, nil, 0)
	require.NoError(t, err)
	_, err = conn.Write([]byte("udp-payload"))
	require.NoError(t, err)
	require.NoError(t, conn.Close())
	require.Equal(t, "udp-payload", <-readDone)
}

func TestDirectIsEmptyConsidersProxyProtocol(t *testing.T) {
	ctx := service.ContextWith[adapter.NetworkManager](context.Background(), emptyTestNetworkManager{})
	ctx = service.ContextWith[adapter.DNSTransportManager](ctx, emptyTestDNSTransportManager{})

	emptyOut, err := NewOutbound(ctx, nil, log.NewNOPFactory().Logger(), "direct", option.DirectOutboundOptions{})
	require.NoError(t, err)
	require.True(t, emptyOut.(*Outbound).IsEmpty())

	ppOut, err := NewOutbound(ctx, nil, log.NewNOPFactory().Logger(), "direct-pp", option.DirectOutboundOptions{
		ProxyProtocol: 1,
	})
	require.NoError(t, err)
	require.False(t, ppOut.(*Outbound).IsEmpty())
}
