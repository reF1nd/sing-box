package direct

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/dialer"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

func TestDirectDomainStrategy(t *testing.T) {
	v4 := netip.MustParseAddr("192.0.2.1")
	v6 := netip.MustParseAddr("2001:db8::1")
	for _, withNetwork := range []bool{false, true} {
		for _, testCase := range []struct {
			name      string
			strategy  C.DomainStrategy
			addresses []netip.Addr
			want      netip.Addr
			wantError string
		}{
			{"as-is", C.DomainStrategyAsIS, []netip.Addr{v6, v4}, v6, ""},
			{"prefer-v4", C.DomainStrategyPreferIPv4, []netip.Addr{v6, v4}, v4, ""},
			{"prefer-v6", C.DomainStrategyPreferIPv6, []netip.Addr{v4, v6}, v6, ""},
			{"v4-only", C.DomainStrategyIPv4Only, []netip.Addr{v6, v4}, v4, ""},
			{"v6-only", C.DomainStrategyIPv6Only, []netip.Addr{v4, v6}, v6, ""},
			{"missing-v4", C.DomainStrategyIPv4Only, []netip.Addr{v6}, netip.Addr{}, "no IPv4 address"},
			{"missing-v6", C.DomainStrategyIPv6Only, []netip.Addr{v4}, netip.Addr{}, "no IPv6 address"},
		} {
			t.Run(testCase.name, func(t *testing.T) {
				outbound := &Outbound{logger: logger.NOP(), dialer: &strategyTestDialer{}, directDomainStrategy: testCase.strategy, fallbackDelay: time.Hour}
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				var conn net.Conn
				var err error
				destination := M.ParseSocksaddr("example.com:443")
				if withNetwork {
					conn, err = outbound.DialParallelNetwork(ctx, "tcp", destination, testCase.addresses, nil, nil, nil, time.Hour)
				} else {
					conn, err = outbound.DialParallel(ctx, "tcp", destination, testCase.addresses)
				}
				if testCase.wantError != "" {
					require.ErrorContains(t, err, testCase.wantError)
					return
				}
				require.NoError(t, err)
				require.Equal(t, testCase.want, conn.(*strategyTestConn).destination.Addr)
			})
		}
	}
}

type strategyTestDialer struct{ dialer.ParallelInterfaceDialer }

func (*strategyTestDialer) DialParallelInterface(_ context.Context, _ string, destination M.Socksaddr, _ *C.NetworkStrategy, _ []C.InterfaceType, _ []C.InterfaceType, _ time.Duration) (net.Conn, error) {
	return &strategyTestConn{destination: destination}, nil
}

type strategyTestConn struct {
	net.Conn
	destination M.Socksaddr
}
