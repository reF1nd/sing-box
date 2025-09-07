package direct

import (
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

type recordingParallelDialer struct {
	parallelResolveDialer
	calls         int
	lastAddresses []netip.Addr
	conn          net.Conn
	listenIndex   int
}

func (d *recordingParallelDialer) DialContext(_ context.Context, _ string, _ M.Socksaddr) (net.Conn, error) {
	d.calls++
	if d.conn != nil {
		return d.conn, nil
	}
	client, server := net.Pipe()
	server.Close()
	return client, nil
}

func (d *recordingParallelDialer) DialParallelNetwork(_ context.Context, _ string, _ M.Socksaddr, destinationAddresses []netip.Addr, _ *C.NetworkStrategy, _ []C.InterfaceType, _ []C.InterfaceType, _ time.Duration) (net.Conn, error) {
	d.calls++
	d.lastAddresses = append([]netip.Addr(nil), destinationAddresses...)
	if d.conn != nil {
		return d.conn, nil
	}
	client, server := net.Pipe()
	server.Close()
	return client, nil
}

type noopPacketConn struct{}

func (noopPacketConn) ReadFrom([]byte) (int, net.Addr, error)    { return 0, nil, io.EOF }
func (noopPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) { return len(p), nil }
func (noopPacketConn) Close() error                              { return nil }
func (noopPacketConn) LocalAddr() net.Addr                       { return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)} }
func (noopPacketConn) SetDeadline(time.Time) error               { return nil }
func (noopPacketConn) SetReadDeadline(time.Time) error           { return nil }
func (noopPacketConn) SetWriteDeadline(time.Time) error          { return nil }

func (d *recordingParallelDialer) ListenSerialNetworkPacket(_ context.Context, destination M.Socksaddr, destinationAddresses []netip.Addr, _ *C.NetworkStrategy, _ []C.InterfaceType, _ []C.InterfaceType, _ time.Duration) (net.PacketConn, netip.Addr, error) {
	d.calls++
	d.lastAddresses = append([]netip.Addr(nil), destinationAddresses...)
	if len(destinationAddresses) > 0 {
		idx := d.listenIndex
		if idx < 0 || idx >= len(destinationAddresses) {
			idx = 0
		}
		return noopPacketConn{}, destinationAddresses[idx], nil
	}
	return noopPacketConn{}, destination.Addr, nil
}

type stubDirectDNSRouter struct {
	adapter.DNSRouter
	records     map[string][]netip.Addr
	lastOptions adapter.DNSQueryOptions
}

func (r *stubDirectDNSRouter) Lookup(_ context.Context, domain string, options adapter.DNSQueryOptions) ([]netip.Addr, error) {
	r.lastOptions = options
	return append([]netip.Addr(nil), r.records[domain]...), nil
}

func TestDirectDomainStrategyDialParallel(t *testing.T) {
	v4a := netip.MustParseAddr("192.0.2.1")
	v4b := netip.MustParseAddr("192.0.2.2")
	v6a := netip.MustParseAddr("2001:db8::1")
	v6b := netip.MustParseAddr("2001:db8::2")
	mixed := []netip.Addr{v4a, v6a, v4b, v6b}
	v6First := []netip.Addr{v6a, v4a, v6b, v4b}
	domainDest := M.ParseSocksaddr("example.com:443")

	cases := []struct {
		name      string
		strategy  C.DomainStrategy
		dest      M.Socksaddr
		input     []netip.Addr
		want      []netip.Addr
		wantError bool
	}{
		{name: "as_is_v4_first", strategy: C.DomainStrategyAsIS, dest: domainDest, input: mixed, want: mixed},
		{name: "as_is_v6_first", strategy: C.DomainStrategyAsIS, dest: domainDest, input: v6First, want: v6First},
		{name: "prefer_ipv4_stable", strategy: C.DomainStrategyPreferIPv4, dest: domainDest, input: v6First, want: []netip.Addr{v4a, v4b, v6a, v6b}},
		{name: "prefer_ipv6_stable", strategy: C.DomainStrategyPreferIPv6, dest: domainDest, input: mixed, want: []netip.Addr{v6a, v6b, v4a, v4b}},
		{name: "prefer_ipv6_v4_only_input", strategy: C.DomainStrategyPreferIPv6, dest: domainDest, input: []netip.Addr{v4a, v4b}, want: []netip.Addr{v4a, v4b}},
		{name: "prefer_ipv4_v6_only_input", strategy: C.DomainStrategyPreferIPv4, dest: domainDest, input: []netip.Addr{v6a, v6b}, want: []netip.Addr{v6a, v6b}},
		{name: "ipv4_only_filters", strategy: C.DomainStrategyIPv4Only, dest: domainDest, input: mixed, want: []netip.Addr{v4a, v4b}},
		{name: "ipv4_only_no_match", strategy: C.DomainStrategyIPv4Only, dest: domainDest, input: []netip.Addr{v6a}, wantError: true},
		{name: "ipv6_only_filters", strategy: C.DomainStrategyIPv6Only, dest: domainDest, input: mixed, want: []netip.Addr{v6a, v6b}},
		{name: "ipv6_only_no_match", strategy: C.DomainStrategyIPv6Only, dest: domainDest, input: []netip.Addr{v4a}, wantError: true},
		{name: "empty_list_domain_delegates_to_resolver", strategy: C.DomainStrategyIPv4Only, dest: domainDest, input: nil, want: nil},
		{name: "empty_list_ip_literal_filtered", strategy: C.DomainStrategyIPv6Only, dest: M.SocksaddrFrom(v4a, 443), input: nil, wantError: true},
		{name: "empty_list_ip_literal_allowed", strategy: C.DomainStrategyIPv4Only, dest: M.SocksaddrFrom(v4a, 443), input: nil, want: []netip.Addr{v4a}},
	}

	for _, tc := range cases {
		for _, useNetwork := range []bool{false, true} {
			suffix := "DialParallel"
			if useNetwork {
				suffix = "DialParallelNetwork"
			}
			t.Run(tc.name+"/"+suffix, func(t *testing.T) {
				rec := &recordingParallelDialer{}
				o := &Outbound{
					Adapter:              outbound.NewAdapter(C.TypeDirect, "direct", []string{N.NetworkTCP, N.NetworkUDP}, nil),
					logger:               logger.NOP(),
					dialer:               rec,
					directDomainStrategy: tc.strategy,
				}
				var (
					conn net.Conn
					err  error
				)
				if useNetwork {
					conn, err = o.DialParallelNetwork(context.Background(), N.NetworkTCP, tc.dest, tc.input, nil, nil, nil, 0)
				} else {
					conn, err = o.DialParallel(context.Background(), N.NetworkTCP, tc.dest, tc.input)
				}
				if tc.wantError {
					require.Error(t, err)
					return
				}
				require.NoError(t, err)
				require.NoError(t, conn.Close())
				require.Equal(t, tc.want, rec.lastAddresses)
			})
		}
	}
}

func TestDirectDialParallelProxyProtocolHeader(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	rec := &recordingParallelDialer{conn: client}
	o := &Outbound{
		Adapter:              outbound.NewAdapter(C.TypeDirect, "direct", []string{N.NetworkTCP}, nil),
		logger:               logger.NOP(),
		dialer:               rec,
		directDomainStrategy: C.DomainStrategyPreferIPv6,
		proxyProto:           1,
	}
	headerCh := make(chan string, 1)
	go func() {
		buf := make([]byte, 128)
		n, _ := server.Read(buf)
		headerCh <- string(buf[:n])
		_, _ = io.Copy(io.Discard, server)
	}()
	ctx := adapter.WithContext(context.Background(), &adapter.InboundContext{
		Source:      M.ParseSocksaddr("192.0.2.10:12345"),
		Destination: M.ParseSocksaddr("198.51.100.20:443"),
	})
	conn, err := o.DialParallel(ctx, N.NetworkTCP, M.ParseSocksaddr("example.com:443"), []netip.Addr{
		netip.MustParseAddr("198.51.100.20"),
		netip.MustParseAddr("2001:db8::20"),
	})
	require.NoError(t, err)
	require.NoError(t, conn.Close())
	require.Equal(t, []netip.Addr{netip.MustParseAddr("2001:db8::20"), netip.MustParseAddr("198.51.100.20")}, rec.lastAddresses)
	require.Equal(t, "PROXY TCP4 192.0.2.10 198.51.100.20 12345 443\r\n", <-headerCh)
}

func TestDirectDomainStrategyAppliesToResolvedDomains(t *testing.T) {
	v4a := netip.MustParseAddr("192.0.2.1")
	v4b := netip.MustParseAddr("192.0.2.2")
	v6a := netip.MustParseAddr("2001:db8::1")
	v6b := netip.MustParseAddr("2001:db8::2")
	dest := M.ParseSocksaddr("ipv6only.example:443")

	for _, entry := range []string{"DialContext", "DialParallel", "DialParallelNetwork"} {
		t.Run("ipv4_only_rejects_aaaa_without_dialing/"+entry, func(t *testing.T) {
			dnsRouter := &stubDirectDNSRouter{records: map[string][]netip.Addr{
				"ipv6only.example": {v6a},
			}}
			ctx := service.ContextWith[adapter.DNSRouter](context.Background(), dnsRouter)
			rec := &recordingParallelDialer{}
			o := &Outbound{
				Adapter:              outbound.NewAdapter(C.TypeDirect, "direct", []string{N.NetworkTCP}, nil),
				ctx:                  ctx,
				logger:               logger.NOP(),
				dialer:               rec,
				directDomainStrategy: C.DomainStrategyIPv4Only,
			}
			var (
				conn net.Conn
				err  error
			)
			switch entry {
			case "DialContext":
				conn, err = o.DialContext(ctx, N.NetworkTCP, dest)
			case "DialParallel":
				conn, err = o.DialParallel(ctx, N.NetworkTCP, dest, nil)
			case "DialParallelNetwork":
				conn, err = o.DialParallelNetwork(ctx, N.NetworkTCP, dest, nil, nil, nil, nil, 0)
			}
			require.Error(t, err)
			require.Nil(t, conn)
			require.Zero(t, rec.calls, "IPv6 dial must never be attempted under ipv4_only")
		})

		t.Run("prefer_ipv6_sorts_resolved_addresses/"+entry, func(t *testing.T) {
			dnsRouter := &stubDirectDNSRouter{records: map[string][]netip.Addr{
				"dual.example": {v4a, v6a, v4b, v6b},
			}}
			ctx := service.ContextWith[adapter.DNSRouter](context.Background(), dnsRouter)
			rec := &recordingParallelDialer{}
			o := &Outbound{
				Adapter:              outbound.NewAdapter(C.TypeDirect, "direct", []string{N.NetworkTCP}, nil),
				ctx:                  ctx,
				logger:               logger.NOP(),
				dialer:               rec,
				directDomainStrategy: C.DomainStrategyPreferIPv6,
			}
			dualDest := M.ParseSocksaddr("dual.example:443")
			var (
				conn net.Conn
				err  error
			)
			switch entry {
			case "DialContext":
				conn, err = o.DialContext(ctx, N.NetworkTCP, dualDest)
			case "DialParallel":
				conn, err = o.DialParallel(ctx, N.NetworkTCP, dualDest, nil)
			case "DialParallelNetwork":
				conn, err = o.DialParallelNetwork(ctx, N.NetworkTCP, dualDest, nil, nil, nil, nil, 0)
			}
			require.NoError(t, err)
			require.NoError(t, conn.Close())
			require.Equal(t, 1, rec.calls)
			require.Equal(t, []netip.Addr{v6a, v6b, v4a, v4b}, rec.lastAddresses)
		})
	}
}

func TestDirectDomainStrategyListenSerialNetworkPacket(t *testing.T) {
	v4a := netip.MustParseAddr("192.0.2.1")
	v4b := netip.MustParseAddr("192.0.2.2")
	v6a := netip.MustParseAddr("2001:db8::1")
	v6b := netip.MustParseAddr("2001:db8::2")
	mixed := []netip.Addr{v4a, v6a, v4b, v6b}
	v6First := []netip.Addr{v6a, v4a, v6b, v4b}

	t.Run("preresolved_and_literal", func(t *testing.T) {
		cases := []struct {
			name      string
			strategy  C.DomainStrategy
			dest      M.Socksaddr
			input     []netip.Addr
			want      []netip.Addr
			wantDest  netip.Addr
			wantError bool
		}{
			{name: "as_is", strategy: C.DomainStrategyAsIS, dest: M.ParseSocksaddr("example.com:53"), input: mixed, want: mixed, wantDest: v4a},
			{name: "prefer_ipv6", strategy: C.DomainStrategyPreferIPv6, dest: M.ParseSocksaddr("example.com:53"), input: mixed, want: []netip.Addr{v6a, v6b, v4a, v4b}, wantDest: v6a},
			{name: "prefer_ipv4", strategy: C.DomainStrategyPreferIPv4, dest: M.ParseSocksaddr("example.com:53"), input: v6First, want: []netip.Addr{v4a, v4b, v6a, v6b}, wantDest: v4a},
			{name: "ipv4_only_filters", strategy: C.DomainStrategyIPv4Only, dest: M.ParseSocksaddr("example.com:53"), input: mixed, want: []netip.Addr{v4a, v4b}, wantDest: v4a},
			{name: "ipv4_only_rejects_v6", strategy: C.DomainStrategyIPv4Only, dest: M.ParseSocksaddr("example.com:53"), input: []netip.Addr{v6a}, wantError: true},
			{name: "ipv6_only_rejects_v4_literal", strategy: C.DomainStrategyIPv6Only, dest: M.SocksaddrFrom(v4a, 53), wantError: true},
			{name: "unspecified_v4_bypasses_filter", strategy: C.DomainStrategyIPv6Only, dest: M.SocksaddrFrom(netip.IPv4Unspecified(), 0), want: nil, wantDest: netip.IPv4Unspecified()},
			{name: "empty_dest_bypasses_filter", strategy: C.DomainStrategyIPv6Only, dest: M.Socksaddr{}, want: nil, wantDest: netip.Addr{}},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				rec := &recordingParallelDialer{}
				o := &Outbound{
					Adapter:              outbound.NewAdapter(C.TypeDirect, "direct", []string{N.NetworkUDP}, nil),
					logger:               logger.NOP(),
					dialer:               rec,
					directDomainStrategy: tc.strategy,
				}
				conn, newDest, err := o.ListenSerialNetworkPacket(context.Background(), tc.dest, tc.input, nil, nil, nil, 0)
				if tc.wantError {
					require.Error(t, err)
					require.Nil(t, conn)
					require.Zero(t, rec.calls)
					return
				}
				require.NoError(t, err)
				require.NoError(t, conn.Close())
				require.Equal(t, 1, rec.calls)
				require.Equal(t, tc.want, rec.lastAddresses)
				require.Equal(t, tc.wantDest, newDest)
			})
		}
	})

	t.Run("resolved_domain_prefer_ipv6_and_return_addr", func(t *testing.T) {
		dnsRouter := &stubDirectDNSRouter{records: map[string][]netip.Addr{
			"dual.example": {v4a, v6a, v4b, v6b},
		}}
		ctx := service.ContextWith[adapter.DNSRouter](context.Background(), dnsRouter)
		rec := &recordingParallelDialer{listenIndex: 1}
		queryOpts := adapter.DNSQueryOptions{
			Strategy:     C.DomainStrategyPreferIPv4,
			DisableCache: true,
		}
		o := &Outbound{
			Adapter:              outbound.NewAdapter(C.TypeDirect, "direct", []string{N.NetworkUDP}, nil),
			ctx:                  ctx,
			logger:               logger.NOP(),
			dialer:               rec,
			domainResolveOptions: queryOpts,
			directDomainStrategy: C.DomainStrategyPreferIPv6,
		}
		conn, newDest, err := o.ListenSerialNetworkPacket(ctx, M.ParseSocksaddr("dual.example:53"), nil, nil, nil, nil, 0)
		require.NoError(t, err)
		require.NoError(t, conn.Close())
		require.Equal(t, 1, rec.calls)
		require.Equal(t, []netip.Addr{v6a, v6b, v4a, v4b}, rec.lastAddresses)
		require.Equal(t, v6b, newDest)
		require.Equal(t, queryOpts, dnsRouter.lastOptions)
	})

	t.Run("resolved_domain_ipv4_only_rejects_aaaa", func(t *testing.T) {
		dnsRouter := &stubDirectDNSRouter{records: map[string][]netip.Addr{
			"ipv6only.example": {v6a},
		}}
		ctx := service.ContextWith[adapter.DNSRouter](context.Background(), dnsRouter)
		rec := &recordingParallelDialer{}
		o := &Outbound{
			Adapter:              outbound.NewAdapter(C.TypeDirect, "direct", []string{N.NetworkUDP}, nil),
			ctx:                  ctx,
			logger:               logger.NOP(),
			dialer:               rec,
			directDomainStrategy: C.DomainStrategyIPv4Only,
		}
		conn, newDest, err := o.ListenSerialNetworkPacket(ctx, M.ParseSocksaddr("ipv6only.example:53"), nil, nil, nil, nil, 0)
		require.Error(t, err)
		require.Nil(t, conn)
		require.False(t, newDest.IsValid())
		require.Zero(t, rec.calls)
	})

	t.Run("resolved_domain_tun_loopback_rejected", func(t *testing.T) {
		dnsRouter := &stubDirectDNSRouter{records: map[string][]netip.Addr{
			"tun.example": {netip.MustParseAddr("172.19.0.2")},
		}}
		ctx := service.ContextWith[adapter.DNSRouter](context.Background(), dnsRouter)
		rec := &recordingParallelDialer{}
		o := &Outbound{
			Adapter:              outbound.NewAdapter(C.TypeDirect, "direct", []string{N.NetworkUDP}, nil),
			ctx:                  ctx,
			logger:               logger.NOP(),
			dialer:               rec,
			directDomainStrategy: C.DomainStrategyPreferIPv4,
		}
		o.myAddresses.Store([]netip.Prefix{netip.MustParsePrefix("172.19.0.1/30")})
		conn, newDest, err := o.ListenSerialNetworkPacket(ctx, M.ParseSocksaddr("tun.example:53"), nil, nil, nil, nil, 0)
		require.ErrorContains(t, err, "loopback connection to TUN range")
		require.Nil(t, conn)
		require.False(t, newDest.IsValid())
		require.Zero(t, rec.calls)
	})
}

func TestDirectIsEmptyConsidersDirectDomainStrategy(t *testing.T) {
	ctx := service.ContextWith[adapter.NetworkManager](context.Background(), emptyTestNetworkManager{})
	ctx = service.ContextWith[adapter.DNSTransportManager](ctx, emptyTestDNSTransportManager{})

	strategyOut, err := NewOutbound(ctx, nil, log.NewNOPFactory().Logger(), "direct-v4", option.DirectOutboundOptions{
		DirectDomainStrategy: option.DomainStrategy(C.DomainStrategyPreferIPv4),
	})
	require.NoError(t, err)
	require.False(t, strategyOut.(*Outbound).IsEmpty())
}
