package direct

import (
	"context"
	"net"
	"net/netip"
	"reflect"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/iponly"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing-tun/ping"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"

	"github.com/pires/go-proxyproto"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.DirectOutboundOptions](registry, C.TypeDirect, NewOutbound)
}

var (
	_ N.ParallelDialer                   = (*Outbound)(nil)
	_ dialer.ParallelNetworkDialer       = (*Outbound)(nil)
	_ dialer.PacketDialerWithDestination = (*Outbound)(nil)
	_ dialer.DirectDialer                = (*Outbound)(nil)
	_ adapter.FlowOutbound               = (*Outbound)(nil)
	_ adapter.FlowOutboundDomainResolver = (*Outbound)(nil)
	_ adapter.InterfaceUpdateListener    = (*Outbound)(nil)
)

type parallelResolveDialer interface {
	dialer.ParallelNetworkDialer
	dialer.PacketDialerWithDestination
}

type Outbound struct {
	outbound.Adapter
	ctx                  context.Context
	logger               logger.ContextLogger
	network              adapter.NetworkManager
	dialer               parallelResolveDialer
	domainResolveOptions adapter.DNSQueryOptions
	domainStrategy       C.DomainStrategy
	directDomainStrategy C.DomainStrategy
	isEmpty              bool
	myAddresses          common.TypedValue[[]netip.Prefix]
	icmpPort             *ping.Port
	proxyProto           uint8
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.DirectOutboundOptions) (adapter.Outbound, error) {
	options.UDPFragmentDefault = true
	if options.Detour != "" {
		return nil, E.New("`detour` is not supported in direct context")
	}
	outboundDialer, err := dialer.NewWithOptions(dialer.Options{
		Context:        ctx,
		Options:        options.DialerOptions,
		RemoteIsDomain: true,
		DirectOutbound: true,
	})
	if err != nil {
		return nil, err
	}
	outbound := &Outbound{
		Adapter: outbound.NewAdapterWithDialerOptions(C.TypeDirect, tag, []string{N.NetworkTCP, N.NetworkUDP, N.NetworkICMP}, options.DialerOptions),
		ctx:     ctx,
		logger:  logger,
		network: service.FromContext[adapter.NetworkManager](ctx),
		//nolint:staticcheck
		domainStrategy:       C.DomainStrategy(options.DomainStrategy),
		directDomainStrategy: C.DomainStrategy(options.DirectDomainStrategy),
		dialer:               outboundDialer.(parallelResolveDialer),
		isEmpty: options.ProxyProtocol == 0 && options.DirectDomainStrategy == 0 && reflect.DeepEqual(options.DialerOptions, option.DialerOptions{
			AbstractDialerOptions: option.AbstractDialerOptions{UDPFragmentDefault: true},
		}),
		proxyProto: options.ProxyProtocol,
	}
	// Snapshot the eagerly resolved options before the dialer's lazy initialization
	// can write them during the first concurrent L4 connection.
	if resolveDialer, loaded := outboundDialer.(dialer.ResolveDialer); loaded {
		outbound.domainResolveOptions = resolveDialer.QueryOptions()
	}
	if options.ProxyProtocol > 2 {
		return nil, E.New("invalid proxy protocol option: ", options.ProxyProtocol)
	}
	if defaultDialer, isDefaultDialer := common.Cast[*dialer.DefaultDialer](outbound.dialer); isDefaultDialer {
		icmpControl := defaultDialer.ICMPControl()
		outbound.icmpPort = ping.NewPort(ctx, logger, func(destination netip.Addr) control.Func {
			return icmpControl
		}, C.ICMPTimeout, C.ICMPFlowMax)
	}
	return outbound, nil
}

func (h *Outbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	switch stage {
	case adapter.StartStateInitialize:
		if h.icmpPort != nil {
			scope.Add(h.icmpPort.Close)
		}
	case adapter.StartStatePostStart, adapter.StartStateStarted:
		if len(h.myAddresses.Load()) == 0 {
			h.fetchMyAddresses()
		}
	}
	return nil
}

func (h *Outbound) fetchMyAddresses() {
	interfaceMonitor := h.network.InterfaceMonitor()
	if interfaceMonitor == nil {
		return
	}
	myInterfaceNames := interfaceMonitor.MyInterfaces()
	if len(myInterfaceNames) == 0 {
		return
	}
	var (
		myAddresses []netip.Prefix
		found       bool
	)
	for _, myInterfaceName := range myInterfaceNames {
		myInterface, err := h.network.InterfaceFinder().ByName(myInterfaceName)
		if err != nil {
			continue
		}
		found = true
		for _, prefix := range myInterface.Addresses {
			if prefix.Addr().Is6() && prefix.Addr().IsLinkLocalUnicast() {
				prefix = netip.PrefixFrom(prefix.Addr(), prefix.Addr().BitLen())
			}
			myAddresses = append(myAddresses, prefix)
		}
	}
	if !found {
		return
	}
	h.myAddresses.Store(myAddresses)
}

func (h *Outbound) InterfaceUpdated(ctx context.Context) {
	h.fetchMyAddresses()
	if h.icmpPort != nil {
		h.icmpPort.Close()
	}
}

func (h *Outbound) isMyLoopbackAddress(addresses ...netip.Addr) bool {
	for _, prefix := range h.myAddresses.Load() {
		for _, address := range addresses {
			if !C.IsDarwin && prefix.Addr() == address {
				continue
			}
			if prefix.Contains(address) {
				return true
			}
		}
	}
	return false
}

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if h.isMyLoopbackAddress(destination.Addr) {
		return nil, E.New("loopback connection to TUN range")
	}
	ctx, metadata := adapter.ExtendContext(ctx)
	originDestination := metadata.Destination
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	network = N.NetworkName(network)
	switch network {
	case N.NetworkTCP:
		h.logger.InfoContext(ctx, "outbound connection to ", destination)
	case N.NetworkUDP:
		h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	}
	var (
		conn net.Conn
		err  error
	)
	if h.directDomainStrategy != C.DomainStrategyAsIS && destination.IsDomain() {
		var destinationAddresses []netip.Addr
		destinationAddresses, err = h.resolveAndApplyDirectDomainStrategy(ctx, destination, nil)
		if err != nil {
			return nil, err
		}
		if len(destinationAddresses) > 0 {
			if h.isMyLoopbackAddress(destinationAddresses...) {
				return nil, E.New("loopback connection to TUN range")
			}
			conn, err = h.dialer.DialParallelNetwork(ctx, network, destination, destinationAddresses, nil, nil, nil, 0)
		} else {
			conn, err = h.dialer.DialContext(ctx, network, destination)
		}
	} else {
		conn, err = h.dialer.DialContext(ctx, network, destination)
	}
	if err != nil {
		return nil, err
	}
	if h.proxyProto > 0 && network == N.NetworkTCP {
		err = h.writeProxyProtocolHeader(conn, metadata.Source, originDestination)
		if err != nil {
			return nil, err
		}
	}
	return conn, nil
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if h.isMyLoopbackAddress(destination.Addr) {
		return nil, E.New("loopback connection to TUN range")
	}
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	h.logger.InfoContext(ctx, "outbound packet connection")
	conn, err := h.dialer.ListenPacket(ctx, destination)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (h *Outbound) ListenPacketWithDestination(ctx context.Context, destination M.Socksaddr) (net.PacketConn, netip.Addr, error) {
	if h.isMyLoopbackAddress(destination.Addr) {
		return nil, netip.Addr{}, E.New("loopback connection to TUN range")
	}
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	h.logger.InfoContext(ctx, "outbound packet connection")
	conn, destinationAddress, err := h.dialer.ListenPacketWithDestination(ctx, destination)
	if err != nil {
		return nil, netip.Addr{}, err
	}
	packetConn := iponly.NewPacketConn(h.logger, conn)
	if destinationAddress.IsValid() && !metadata.UDPDisableDomainUnmapping {
		return bufio.NewNATPacketConn(packetConn, M.SocksaddrFrom(destinationAddress, destination.Port), destination), netip.Addr{}, nil
	}
	return packetConn, destinationAddress, nil
}

func (h *Outbound) PreMatchFlow(network string, destination netip.Addr) adapter.PreMatchAction {
	if network == N.NetworkICMP && h.icmpPort != nil {
		if h.isMyLoopbackAddress(destination) {
			h.logger.Error("reject ", network, " connection to ", destination, ": loopback connection to TUN range")
			return adapter.PreMatchReject
		}
		return adapter.PreMatchFlow
	}
	return adapter.PreMatchContinue
}

func (h *Outbound) FlowDomainResolveOptions() adapter.DNSQueryOptions {
	return h.domainResolveOptions
}

func (h *Outbound) PortAddresses() (netip.Addr, netip.Addr) {
	return h.icmpPort.PortAddresses()
}

func (h *Outbound) PortMTU() uint32 {
	return h.icmpPort.PortMTU()
}

func (h *Outbound) AttachReturn(returnPath tun.Return) error {
	return h.icmpPort.AttachReturn(returnPath)
}

func (h *Outbound) DetachReturn(returnPath tun.Return) error {
	return h.icmpPort.DetachReturn(returnPath)
}

func (h *Outbound) WritePackets(packets [][]byte) error {
	return h.icmpPort.WritePackets(packets)
}

func (h *Outbound) DialParallel(ctx context.Context, network string, destination M.Socksaddr, destinationAddresses []netip.Addr) (net.Conn, error) {
	if h.isMyLoopbackAddress(destinationAddresses...) || destination.IsIP() && h.isMyLoopbackAddress(destination.Addr) {
		return nil, E.New("loopback connection to TUN range")
	}
	ctx, metadata := adapter.ExtendContext(ctx)
	originDestination := metadata.Destination
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	network = N.NetworkName(network)
	switch network {
	case N.NetworkTCP:
		h.logger.InfoContext(ctx, "outbound connection to ", destination)
	case N.NetworkUDP:
		h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	}
	destinationAddresses, err := h.resolveAndApplyDirectDomainStrategy(ctx, destination, destinationAddresses)
	if err != nil {
		return nil, err
	}
	if h.isMyLoopbackAddress(destinationAddresses...) {
		return nil, E.New("loopback connection to TUN range")
	}
	conn, err := h.dialer.DialParallelNetwork(ctx, network, destination, destinationAddresses, nil, nil, nil, 0)
	if err != nil {
		return nil, err
	}
	if h.proxyProto > 0 && network == N.NetworkTCP {
		err = h.writeProxyProtocolHeader(conn, metadata.Source, originDestination)
		if err != nil {
			return nil, err
		}
	}
	return conn, nil
}

func (h *Outbound) DialParallelNetwork(ctx context.Context, network string, destination M.Socksaddr, destinationAddresses []netip.Addr, networkStrategy *C.NetworkStrategy, networkType []C.InterfaceType, fallbackNetworkType []C.InterfaceType, fallbackDelay time.Duration) (net.Conn, error) {
	if h.isMyLoopbackAddress(destinationAddresses...) || destination.IsIP() && h.isMyLoopbackAddress(destination.Addr) {
		return nil, E.New("loopback connection to TUN range")
	}
	ctx, metadata := adapter.ExtendContext(ctx)
	originDestination := metadata.Destination
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	network = N.NetworkName(network)
	switch network {
	case N.NetworkTCP:
		h.logger.InfoContext(ctx, "outbound connection to ", destination)
	case N.NetworkUDP:
		h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	}
	destinationAddresses, err := h.resolveAndApplyDirectDomainStrategy(ctx, destination, destinationAddresses)
	if err != nil {
		return nil, err
	}
	if h.isMyLoopbackAddress(destinationAddresses...) {
		return nil, E.New("loopback connection to TUN range")
	}
	conn, err := h.dialer.DialParallelNetwork(ctx, network, destination, destinationAddresses, networkStrategy, networkType, fallbackNetworkType, fallbackDelay)
	if err != nil {
		return nil, err
	}
	if h.proxyProto > 0 && network == N.NetworkTCP {
		err = h.writeProxyProtocolHeader(conn, metadata.Source, originDestination)
		if err != nil {
			return nil, err
		}
	}
	return conn, nil
}

func (h *Outbound) resolveAndApplyDirectDomainStrategy(ctx context.Context, destination M.Socksaddr, destinationAddresses []netip.Addr) ([]netip.Addr, error) {
	if len(destinationAddresses) == 0 {
		if destination.IsDomain() {
			if h.directDomainStrategy == C.DomainStrategyAsIS {
				return nil, nil
			}
			var dnsRouter adapter.DNSRouter
			if h.ctx != nil {
				dnsRouter = service.FromContext[adapter.DNSRouter](h.ctx)
			}
			if dnsRouter == nil && ctx != nil {
				dnsRouter = service.FromContext[adapter.DNSRouter](ctx)
			}
			if dnsRouter == nil {
				return nil, nil
			}
			lookupCtx := log.ContextWithOverrideLevel(ctx, log.LevelDebug)
			var err error
			destinationAddresses, err = dnsRouter.Lookup(lookupCtx, destination.Fqdn, h.domainResolveOptions)
			if err != nil {
				return nil, err
			}
		} else if destination.Addr.IsValid() {
			destinationAddresses = []netip.Addr{destination.Addr}
		}
	}
	return h.applyDirectDomainStrategy(destination, destinationAddresses)
}

func (h *Outbound) applyDirectDomainStrategy(destination M.Socksaddr, destinationAddresses []netip.Addr) ([]netip.Addr, error) {
	switch h.directDomainStrategy {
	case C.DomainStrategyAsIS:
		return destinationAddresses, nil
	case C.DomainStrategyPreferIPv4:
		return sortAddressesByFamily(destinationAddresses, false), nil
	case C.DomainStrategyPreferIPv6:
		return sortAddressesByFamily(destinationAddresses, true), nil
	case C.DomainStrategyIPv4Only:
		filtered := common.Filter(destinationAddresses, netip.Addr.Is4)
		if len(filtered) == 0 {
			return nil, E.New("no IPv4 address available for ", destination)
		}
		return filtered, nil
	case C.DomainStrategyIPv6Only:
		filtered := common.Filter(destinationAddresses, netip.Addr.Is6)
		if len(filtered) == 0 {
			return nil, E.New("no IPv6 address available for ", destination)
		}
		return filtered, nil
	default:
		return destinationAddresses, nil
	}
}

func sortAddressesByFamily(addresses []netip.Addr, preferIPv6 bool) []netip.Addr {
	if len(addresses) <= 1 {
		return addresses
	}
	sorted := make([]netip.Addr, 0, len(addresses))
	for _, addr := range addresses {
		if addr.Is6() == preferIPv6 {
			sorted = append(sorted, addr)
		}
	}
	for _, addr := range addresses {
		if addr.Is6() != preferIPv6 {
			sorted = append(sorted, addr)
		}
	}
	return sorted
}

func (h *Outbound) ListenSerialNetworkPacket(ctx context.Context, destination M.Socksaddr, destinationAddresses []netip.Addr, networkStrategy *C.NetworkStrategy, networkType []C.InterfaceType, fallbackNetworkType []C.InterfaceType, fallbackDelay time.Duration) (net.PacketConn, netip.Addr, error) {
	if h.isMyLoopbackAddress(destinationAddresses...) || destination.IsIP() && h.isMyLoopbackAddress(destination.Addr) {
		return nil, netip.Addr{}, E.New("loopback connection to TUN range")
	}
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	h.logger.InfoContext(ctx, "outbound packet connection")
	if len(destinationAddresses) > 0 || destination.IsDomain() || (destination.Addr.IsValid() && !destination.Addr.IsUnspecified()) {
		var err error
		destinationAddresses, err = h.resolveAndApplyDirectDomainStrategy(ctx, destination, destinationAddresses)
		if err != nil {
			return nil, netip.Addr{}, err
		}
		if h.isMyLoopbackAddress(destinationAddresses...) {
			return nil, netip.Addr{}, E.New("loopback connection to TUN range")
		}
	}
	conn, newDestination, err := h.dialer.ListenSerialNetworkPacket(ctx, destination, destinationAddresses, networkStrategy, networkType, fallbackNetworkType, fallbackDelay)
	if err != nil {
		return nil, netip.Addr{}, err
	}
	return iponly.NewPacketConn(h.logger, conn), newDestination, nil
}

func (h *Outbound) writeProxyProtocolHeader(conn net.Conn, source M.Socksaddr, destination M.Socksaddr) error {
	if !source.IsValid() {
		source = M.SocksaddrFromNet(conn.LocalAddr())
	}
	source = source.Unwrap()
	destination = destination.Unwrap()
	if !source.Addr.IsValid() || !destination.Addr.IsValid() {
		conn.Close()
		return E.New("write proxy protocol header: invalid source or destination address")
	}
	if destination.Addr.Is6() {
		source = M.SocksaddrFrom(netip.AddrFrom16(source.Addr.As16()), source.Port)
	}
	header := proxyproto.HeaderProxyFromAddrs(h.proxyProto, source.TCPAddr(), destination.TCPAddr())
	if header.Command != proxyproto.PROXY || header.TransportProtocol == proxyproto.UNSPEC {
		conn.Close()
		return E.New("write proxy protocol header: unsupported address pair")
	}
	_, err := header.WriteTo(conn)
	if err != nil {
		conn.Close()
		return E.Cause(err, "write proxy protocol header")
	}
	return nil
}

func (h *Outbound) IsEmpty() bool {
	return h.isEmpty
}
