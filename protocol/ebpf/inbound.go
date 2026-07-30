//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"net"
	"net/netip"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	ECommon "github.com/sagernet/sing-box/common/ebpf"
	"github.com/sagernet/sing-box/common/listener"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	udpnat "github.com/sagernet/sing/common/udpnat2"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

const (
	defaultListenPort      = 65532
	androidTetheringDNSUID = 1052
	dnsModeHijack          = "hijack"
	dnsModeOff             = "off"
)

var defaultRedirectIPv4 = netip.MustParsePrefix("127.128.0.0/9")

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.EBPFInboundOptions](registry, C.TypeEBPF, NewInbound)
}

type Inbound struct {
	inbound.Adapter
	ctx               context.Context
	router            adapter.ConnectionRouterEx
	logger            log.ContextLogger
	networkManager    adapter.NetworkManager
	listenOptions     option.ListenOptions
	cgroupPath        string
	listener4         *listener.Listener
	listener6         *listener.Listener
	udpNat            *udpnat.Service
	backend           *ECommon.Backend
	protectRegistered bool
	listenPort        uint16
	enableTCP         bool
	enableUDP         bool
	dnsMode           string
	redirectIPv4      netip.Prefix
	redirectIPv6      netip.Prefix
	policy            ECommon.Policy
	localRoutes       []*localRoute
	sharedOptions     option.EBPFSharedNetworkOptions
	sharedNetwork     *sharedNetwork
	backendAccess     sync.RWMutex
	closeAccess       sync.Mutex
	statsCancel       context.CancelFunc
	statsDone         chan struct{}

	bypassRuleSetAccess    sync.Mutex
	bypassRuleSet          []adapter.RuleSet
	bypassRuleSetCallbacks []*list.Element[adapter.RuleSetUpdateCallback]
	bypassRuleSetStarted   bool

	udpClients udpClientTable
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.EBPFInboundOptions) (adapter.Inbound, error) {
	listenOptions, err := normalizeListenOptions(options.ListenOptions)
	if err != nil {
		return nil, err
	}
	cgroupPath, err := normalizeCgroupPath(options.CgroupPath)
	if err != nil {
		return nil, err
	}
	redirectIPv4, redirectIPv6, err := normalizeRedirectAddresses(options.RedirectAddress)
	if err != nil {
		return nil, err
	}
	dnsMode, err := normalizeDNSMode(options.DNSMode)
	if err != nil {
		return nil, err
	}
	includeUID, err := parseUIDRanges(options.IncludeUID, options.IncludeUIDRange)
	if err != nil {
		return nil, E.Cause(err, "parse include_uid_range")
	}
	excludeUID, err := parseUIDRanges(options.ExcludeUID, options.ExcludeUIDRange)
	if err != nil {
		return nil, E.Cause(err, "parse exclude_uid_range")
	}
	excludeUID = append(excludeUID, platformExcludedUIDRanges(runtime.GOOS)...)
	sharedOptions, err := normalizeSharedNetworkOptions(options.SharedNetwork)
	if err != nil {
		return nil, err
	}
	network := options.Network.Build()
	enableTCP := common.Contains(network, N.NetworkTCP)
	enableUDP := common.Contains(network, N.NetworkUDP)
	if err = validateSharedNetworkProtocols(sharedOptions, enableUDP, dnsMode); err != nil {
		return nil, err
	}
	networkManager := service.FromContext[adapter.NetworkManager](ctx)
	if networkManager == nil {
		return nil, E.New("missing network manager")
	}
	inbound := &Inbound{
		Adapter:        inbound.NewAdapter(C.TypeEBPF, tag),
		ctx:            ctx,
		router:         router,
		logger:         logger,
		networkManager: networkManager,
		listenOptions:  listenOptions,
		cgroupPath:     cgroupPath,
		listenPort:     listenOptions.ListenPort,
		enableTCP:      enableTCP,
		enableUDP:      enableUDP,
		dnsMode:        dnsMode,
		redirectIPv4:   redirectIPv4,
		redirectIPv6:   redirectIPv6,
		sharedOptions:  sharedOptions,
		policy: ECommon.Policy{
			HijackDNS:  dnsMode == dnsModeHijack,
			IncludeUID: includeUID,
			ExcludeUID: excludeUID,
		},
	}
	for _, ruleSetTag := range options.BypassRuleSet {
		ruleSet, loaded := router.RuleSet(ruleSetTag)
		if !loaded {
			return nil, E.New("parse bypass_rule_set: rule-set not found: ", ruleSetTag)
		}
		inbound.bypassRuleSet = append(inbound.bypassRuleSet, ruleSet)
	}
	udpTimeout := C.UDPTimeout
	if listenOptions.UDPTimeout != 0 {
		udpTimeout = time.Duration(listenOptions.UDPTimeout)
	}
	inbound.udpNat = udpnat.New(inbound, inbound.preparePacketConnection, udpTimeout, false)
	if redirectIPv4.IsValid() {
		inbound.listener4 = inbound.newListener(network, false)
	}
	if redirectIPv6.IsValid() {
		inbound.listener6 = inbound.newListener(network, true)
	}
	return inbound, nil
}

func normalizeDNSMode(mode string) (string, error) {
	switch mode {
	case "", dnsModeHijack:
		return dnsModeHijack, nil
	case dnsModeOff:
		return dnsModeOff, nil
	default:
		return "", E.New("unknown eBPF dns_mode: ", mode)
	}
}

func normalizeCgroupPath(cgroupPath string) (string, error) {
	if cgroupPath == "" {
		return "", nil
	}
	if !filepath.IsAbs(cgroupPath) {
		return "", E.New("eBPF cgroup_path must be absolute")
	}
	return filepath.Clean(cgroupPath), nil
}

func (i *Inbound) newListener(network []string, ipv6 bool) *listener.Listener {
	listenOptions := i.listenOptions
	listenAddress := netip.IPv4Unspecified()
	if ipv6 {
		listenAddress = netip.IPv6Unspecified()
	}
	listenOptions.Listen = common.Ptr(badoption.Addr(listenAddress))
	return listener.New(listener.Options{
		Context:             i.ctx,
		Logger:              i.logger,
		Network:             network,
		Listen:              listenOptions,
		ConnectionHandler:   i,
		OOBPacketHandler:    i,
		DisablePacketOutput: true,
		SocketControl:       i.socketControl(ipv6),
	})
}

func normalizeListenOptions(options option.ListenOptions) (option.ListenOptions, error) {
	if options.NetNs != "" {
		return option.ListenOptions{}, E.New("netns is not supported by eBPF inbound")
	}
	if options.BindInterface != "" && options.BindInterface != "lo" {
		return option.ListenOptions{}, E.New("eBPF inbound bind_interface must be lo")
	}
	if options.Listen != nil {
		listenAddress := netip.Addr(*options.Listen)
		if !listenAddress.IsValid() || !listenAddress.IsUnspecified() {
			return option.ListenOptions{}, E.New("eBPF inbound listen address must be unspecified")
		}
	}
	if options.ProxyProtocol || options.ProxyProtocolAcceptNoHeader {
		return option.ListenOptions{}, E.New("proxy_protocol is not supported by eBPF inbound")
	}
	options.Listen = common.Ptr(badoption.Addr(netip.IPv4Unspecified()))
	if options.ListenPort == 0 {
		options.ListenPort = defaultListenPort
	}
	return options, nil
}

func normalizeRedirectAddresses(addresses []netip.Prefix) (netip.Prefix, netip.Prefix, error) {
	if len(addresses) == 0 {
		return defaultRedirectIPv4, netip.Prefix{}, nil
	}
	var ipv4Prefix netip.Prefix
	var ipv6Prefix netip.Prefix
	for _, address := range addresses {
		if !address.IsValid() {
			return netip.Prefix{}, netip.Prefix{}, E.New("invalid eBPF redirect address")
		}
		address = address.Masked()
		if err := ECommon.ValidateRedirectPrefix(address); err != nil {
			return netip.Prefix{}, netip.Prefix{}, err
		}
		switch {
		case address.Addr().Is4():
			if ipv4Prefix.IsValid() {
				return netip.Prefix{}, netip.Prefix{}, E.New("duplicate IPv4 eBPF redirect address")
			}
			ipv4Prefix = address
		case address.Addr().Is6() && !address.Addr().Is4In6():
			if ipv6Prefix.IsValid() {
				return netip.Prefix{}, netip.Prefix{}, E.New("duplicate IPv6 eBPF redirect address")
			}
			ipv6Prefix = address
		default:
			return netip.Prefix{}, netip.Prefix{}, E.New("invalid eBPF redirect address family: ", address)
		}
	}
	return ipv4Prefix, ipv6Prefix, nil
}

func parseUIDRanges(uidList []uint32, rangeList []string) ([]ECommon.UIDRange, error) {
	uidRanges := make([]ECommon.UIDRange, 0, len(uidList)+len(rangeList))
	for _, uid := range uidList {
		uidRanges = append(uidRanges, ECommon.UIDRange{Start: uid, End: uid})
	}
	for _, uidRange := range rangeList {
		separator := strings.IndexByte(uidRange, ':')
		if separator < 0 {
			return nil, E.New("missing ':' in range: ", uidRange)
		}
		if separator == 0 {
			return nil, E.New("missing range start: ", uidRange)
		}
		if separator == len(uidRange)-1 {
			return nil, E.New("missing range end: ", uidRange)
		}
		start, err := strconv.ParseUint(uidRange[:separator], 0, 32)
		if err != nil {
			return nil, E.Cause(err, "parse range start")
		}
		end, err := strconv.ParseUint(uidRange[separator+1:], 0, 32)
		if err != nil {
			return nil, E.Cause(err, "parse range end")
		}
		if start > end {
			return nil, E.New("range start is greater than range end: ", uidRange)
		}
		uidRanges = append(uidRanges, ECommon.UIDRange{Start: uint32(start), End: uint32(end)})
	}
	return uidRanges, nil
}

func platformExcludedUIDRanges(goos string) []ECommon.UIDRange {
	if goos != "android" {
		return nil
	}
	return []ECommon.UIDRange{{Start: androidTetheringDNSUID, End: androidTetheringDNSUID}}
}

func (i *Inbound) Start(stage adapter.StartStage) error {
	switch stage {
	case adapter.StartStateInitialize:
		policy := i.policy
		policy.EnableBypassCIDR = true
		backend, err := ECommon.Prepare(i.cgroupPath, i.listenPort,
			i.enableTCP, i.enableUDP, i.redirectIPv4, i.redirectIPv6, policy)
		if err != nil {
			return err
		}
		i.setBackend(backend)
		if err = i.networkManager.RegisterSocketProtectFunc(backend.ProtectFunc()); err != nil {
			closeErr := backend.Close()
			if backend.IsClosed() {
				i.setBackend(nil)
			}
			if closeErr != nil {
				closeErr = E.Cause(closeErr, "close eBPF backend")
			}
			return E.Errors(err, closeErr)
		}
		i.protectRegistered = true
		if i.sharedOptions.Enabled {
			i.sharedNetwork = newSharedNetwork(i, i.sharedOptions)
		}
	case adapter.StartStateStart:
		backend := i.backendInstance()
		if backend == nil {
			return E.New("eBPF backend is not initialized")
		}
		if err := i.startBypassRuleSets(); err != nil {
			return combineStartError(
				E.Cause(err, "initialize eBPF bypass_rule_set"),
				i.cleanupStartFailure(),
			)
		}
		if err := i.setupLocalRoutes(); err != nil {
			return combineStartError(
				E.Cause(err, "configure eBPF redirect routes"),
				i.cleanupStartFailure(),
			)
		}
		if err := i.startListeners(); err != nil {
			return combineStartError(err, i.cleanupStartFailure())
		}
		if i.sharedNetwork != nil {
			if err := i.sharedNetwork.Start(backend); err != nil {
				return combineStartError(err, i.cleanupStartFailure())
			}
		}
		if err := backend.Attach(); err != nil {
			return combineStartError(err, i.cleanupStartFailure())
		}
		i.startRuntimeStatsMonitor(backend)
		bypassIPv4Count, bypassIPv6Count := backend.BypassCIDRCount()
		i.logger.Info(
			"eBPF inbound attached: cgroup=", backend.CgroupPath(),
			", dns_mode=", i.dnsMode,
			", redirect_address=[", strings.Join(i.redirectAddressStrings(), ", "), "]",
			", bypass_cidr={ipv4:", bypassIPv4Count, ", ipv6:", bypassIPv6Count, "}",
			", redirect_map_capacity={tcp:", ECommon.TCPRedirectMapCapacity,
			", udp:", ECommon.UDPRedirectMapCapacity, "}",
			", programs=[", strings.Join(backend.AttachedPrograms(), ", "), "]",
		)
	}
	return nil
}

func combineStartError(startErr error, cleanupErr error) error {
	if cleanupErr == nil {
		return startErr
	}
	return E.Errors(startErr, E.Cause(cleanupErr, "cleanup eBPF inbound"))
}

func (i *Inbound) Close() error {
	i.closeAccess.Lock()
	defer i.closeAccess.Unlock()
	i.stopRuntimeStatsMonitor()
	i.udpNat.Purge()
	i.stopBypassRuleSets()
	var sharedErr error
	if i.sharedNetwork != nil {
		sharedErr = i.sharedNetwork.Close()
		if !i.sharedNetwork.IsClosed() {
			if sharedErr == nil {
				sharedErr = E.New("shared-network eBPF backend remained open after close")
			}
			return sharedErr
		}
		i.sharedNetwork = nil
	}
	backend := i.backendInstance()
	var backendErr error
	if backend != nil {
		backendErr = backend.Close()
		if !backend.IsClosed() {
			if backendErr == nil {
				backendErr = E.New("eBPF backend remained open after close")
			}
			return backendErr
		}
		i.setBackend(nil)
	}
	i.unregisterSocketProtector()
	return E.Errors(sharedErr, backendErr, i.closeListeners(), i.removeLocalRoutes())
}

func (i *Inbound) startListeners() error {
	if i.listener4 != nil {
		if err := i.listener4.Start(); err != nil {
			return err
		}
	}
	if i.listener6 != nil {
		if err := i.listener6.Start(); err != nil {
			return err
		}
	}
	return nil
}

func (i *Inbound) closeListeners() error {
	var listener4Err error
	var listener6Err error
	if i.listener4 != nil {
		listener4Err = i.listener4.Close()
	}
	if i.listener6 != nil {
		listener6Err = i.listener6.Close()
	}
	return E.Errors(listener4Err, listener6Err)
}

func (i *Inbound) cleanupStartFailure() error {
	i.stopRuntimeStatsMonitor()
	i.udpNat.Purge()
	i.stopBypassRuleSets()
	var sharedErr error
	if i.sharedNetwork != nil {
		sharedErr = i.sharedNetwork.Close()
		if !i.sharedNetwork.IsClosed() {
			if sharedErr == nil {
				sharedErr = E.New("shared-network eBPF backend remained open after close")
			}
			return sharedErr
		}
		i.sharedNetwork = nil
	}
	backend := i.backendInstance()
	var backendErr error
	if backend != nil {
		backendErr = backend.Close()
		if !backend.IsClosed() {
			if backendErr == nil {
				backendErr = E.New("eBPF backend remained open after close")
			}
			return backendErr
		}
		i.setBackend(nil)
	}
	i.unregisterSocketProtector()
	return E.Errors(sharedErr, backendErr, i.closeListeners(), i.removeLocalRoutes())
}

func (i *Inbound) backendInstance() *ECommon.Backend {
	i.backendAccess.RLock()
	defer i.backendAccess.RUnlock()
	return i.backend
}

func (i *Inbound) setBackend(backend *ECommon.Backend) {
	i.backendAccess.Lock()
	i.backend = backend
	i.backendAccess.Unlock()
}

func (i *Inbound) redirectAddressStrings() []string {
	addresses := make([]string, 0, 2)
	if i.redirectIPv4.IsValid() {
		addresses = append(addresses, i.redirectIPv4.String())
	}
	if i.redirectIPv6.IsValid() {
		addresses = append(addresses, i.redirectIPv6.String())
	}
	return addresses
}

func (i *Inbound) unregisterSocketProtector() {
	if !i.protectRegistered {
		return
	}
	i.networkManager.UnregisterSocketProtectFunc()
	i.protectRegistered = false
}

func (i *Inbound) startBypassRuleSets() error {
	i.bypassRuleSetAccess.Lock()
	defer i.bypassRuleSetAccess.Unlock()
	if i.bypassRuleSetStarted {
		return nil
	}
	i.bypassRuleSetCallbacks = make([]*list.Element[adapter.RuleSetUpdateCallback], 0, len(i.bypassRuleSet))
	for _, ruleSet := range i.bypassRuleSet {
		ruleSet.IncRef()
		i.bypassRuleSetCallbacks = append(
			i.bypassRuleSetCallbacks,
			ruleSet.RegisterCallback(i.updateBypassRuleSet),
		)
	}
	i.bypassRuleSetStarted = true
	updated, err := i.refreshBypassRuleSetsLocked(true)
	if err != nil {
		i.stopBypassRuleSetsLocked()
		return err
	}
	if updated {
		i.logBypassCIDRUpdate()
	}
	return nil
}

func (i *Inbound) stopBypassRuleSets() {
	i.bypassRuleSetAccess.Lock()
	defer i.bypassRuleSetAccess.Unlock()
	i.stopBypassRuleSetsLocked()
}

func (i *Inbound) stopBypassRuleSetsLocked() {
	if !i.bypassRuleSetStarted {
		return
	}
	for ruleSetIndex, ruleSet := range i.bypassRuleSet {
		if ruleSetIndex < len(i.bypassRuleSetCallbacks) {
			ruleSet.UnregisterCallback(i.bypassRuleSetCallbacks[ruleSetIndex])
		}
		ruleSet.DecRef()
	}
	i.bypassRuleSetCallbacks = nil
	i.bypassRuleSetStarted = false
}

func (i *Inbound) updateBypassRuleSet(adapter.RuleSet) {
	i.bypassRuleSetAccess.Lock()
	defer i.bypassRuleSetAccess.Unlock()
	if !i.bypassRuleSetStarted {
		return
	}
	updated, err := i.refreshBypassRuleSetsLocked(false)
	if err != nil {
		backend := i.backendInstance()
		if backend != nil && !backend.IsClosed() {
			i.logger.Error("refresh eBPF bypass_rule_set: ", err)
		}
		return
	}
	if updated {
		i.logBypassCIDRUpdate()
	}
}

func (i *Inbound) refreshBypassRuleSetsLocked(warnEmpty bool) (bool, error) {
	prefixes := i.localInterfacePrefixes()
	for _, ruleSet := range i.bypassRuleSet {
		ipSets := ruleSet.ExtractIPSet()
		if warnEmpty && len(ipSets) == 0 {
			i.logger.Warn("bypass_rule_set: no destination IP CIDR rules found in rule-set: ", ruleSet.Name())
		}
		for _, ipSet := range ipSets {
			prefixes = append(prefixes, ipSet.Prefixes()...)
		}
	}
	backend := i.backendInstance()
	if backend == nil {
		return false, E.New("eBPF backend is not initialized")
	}
	return backend.UpdateBypassCIDR(prefixes)
}

func (i *Inbound) localInterfacePrefixes() []netip.Prefix {
	return localInterfacePrefixes(i.networkManager.InterfaceFinder().Interfaces())
}

func localInterfacePrefixes(interfaces []control.Interface) []netip.Prefix {
	var prefixes []netip.Prefix
	for _, networkInterface := range interfaces {
		for _, prefix := range networkInterface.Addresses {
			if !prefix.IsValid() {
				continue
			}
			prefix = prefix.Masked()
			address := prefix.Addr().Unmap()
			prefixBits := prefix.Bits()
			if prefix.Addr().Is4In6() {
				if prefixBits < 96 {
					continue
				}
				prefixBits -= 96
			}
			if address.IsUnspecified() || address.IsLoopback() {
				continue
			}
			prefixes = append(prefixes, netip.PrefixFrom(address, prefixBits).Masked())
		}
	}
	return prefixes
}

func (i *Inbound) logBypassCIDRUpdate() {
	backend := i.backendInstance()
	if backend == nil {
		return
	}
	ipv4Count, ipv6Count := backend.BypassCIDRCount()
	i.logger.Debug("refreshed eBPF bypass CIDR policy: ipv4=", ipv4Count, ", ipv6=", ipv6Count)
}

func (i *Inbound) InterfaceUpdated() {
	i.udpNat.Purge()
	i.bypassRuleSetAccess.Lock()
	if i.bypassRuleSetStarted {
		updated, err := i.refreshBypassRuleSetsLocked(false)
		if err != nil {
			i.logger.Error("refresh eBPF local interface bypass: ", err)
		} else if updated {
			i.logBypassCIDRUpdate()
		}
	}
	i.bypassRuleSetAccess.Unlock()
	if i.sharedNetwork != nil {
		i.sharedNetwork.InterfaceUpdated()
	}
}

func (i *Inbound) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	backend := i.backendInstance()
	if backend == nil {
		conn.Close()
		return
	}
	original, err := backend.TakeOriginal(
		ECommon.ProtocolTCP,
		M.SocksaddrFromNet(conn.LocalAddr()).AddrPort(),
	)
	if err != nil {
		i.logger.ErrorContext(ctx, "lookup TCP original destination: ", err)
		conn.Close()
		return
	}
	metadata.Inbound = i.Tag()
	metadata.InboundType = i.Type()
	metadata.Destination = M.SocksaddrFromNetIP(original.Destination)
	metadata.Source, err = restoreOriginalSource(metadata.Source, original.Destination.Addr(), original.UID)
	if err != nil {
		i.logger.DebugContext(ctx, "restore TCP original source: ", err)
	}
	i.logger.InfoContext(ctx, "inbound connection to ", metadata.Destination)
	i.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}

func (i *Inbound) NewPacket(buffer *buf.Buffer, oob []byte, source M.Socksaddr) {
	backend := i.backendInstance()
	if backend == nil {
		return
	}
	redirectAddress, err := redirectAddressFromOOB(oob)
	if err != nil {
		i.logger.Warn("read UDP redirect address: ", err)
		return
	}
	client := source.AddrPort()
	redirectDestination := netip.AddrPortFrom(redirectAddress, i.listenPort)
	original, err := backend.LookupOriginal(ECommon.ProtocolUDP, redirectDestination)
	if err != nil {
		i.logger.Warn("lookup UDP original destination: ", err)
		return
	}
	releasedRedirects := i.udpClients.setBinding(
		client,
		original.Destination,
		redirectAddress,
		original.ConnectedUDP,
	)
	i.udpClients.setUID(client, original.UID)
	i.deleteUDPRedirects(releasedRedirects)
	i.udpNat.NewPacket([][]byte{buffer.Bytes()}, source, M.SocksaddrFromNetIP(original.Destination), original.ConnectedUDP)
}

func (i *Inbound) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	metadata := adapter.InboundContext{
		Inbound:     i.Tag(),
		InboundType: i.Type(),
		Source:      source,
		Destination: destination,
	}
	//nolint:staticcheck
	metadata.InboundDetour = i.listenOptions.Detour
	if clientState, loaded := i.udpClients.load(source.AddrPort()); loaded {
		metadata.UDPConnect = clientState.isConnected()
		var err error
		metadata.Source, err = restoreOriginalSource(source, destination.Addr, clientState.sourceUID())
		if err != nil {
			i.logger.DebugContext(ctx, "restore UDP original source: ", err)
		}
	}
	i.logger.InfoContext(ctx, "inbound packet connection from ", metadata.Source)
	i.logger.InfoContext(ctx, "inbound packet connection to ", destination)
	i.router.RoutePacketConnectionEx(ctx, conn, metadata, onClose)
}

func (i *Inbound) preparePacketConnection(source M.Socksaddr, destination M.Socksaddr, userData any) (bool, context.Context, N.PacketWriter, N.CloseHandlerFunc) {
	connectedUDP, _ := userData.(bool)
	ctx := log.ContextWithNewID(i.ctx)
	client := source.AddrPort()
	clientState := i.udpClients.loadOrCreate(client)
	clientState.setConnected(connectedUDP)
	writer := &udpPacketWriter{
		inbound:     i,
		client:      client,
		clientState: clientState,
	}
	return true, ctx, writer, func(error) {
		i.deleteUDPRedirects(i.udpClients.delete(writer.client, writer.clientState))
	}
}

func (i *Inbound) deleteUDPRedirects(redirectAddresses []netip.Addr) {
	if len(redirectAddresses) == 0 {
		return
	}
	backend := i.backendInstance()
	if backend == nil {
		return
	}
	for _, redirectAddress := range redirectAddresses {
		redirect := netip.AddrPortFrom(redirectAddress, i.listenPort)
		if err := backend.DeleteRedirect(ECommon.ProtocolUDP, redirect); err != nil {
			i.logger.Warn("delete UDP redirect mapping for ", redirect, ": ", err)
		}
	}
}

func (i *Inbound) socketControl(ipv6Listener bool) control.Func {
	return func(network string, address string, rawConn syscall.RawConn) error {
		if ipv6Listener {
			return control.Raw(rawConn, func(fd uintptr) error {
				if err := unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_V6ONLY, 1); err != nil {
					return err
				}
				if strings.HasPrefix(network, "udp") {
					return unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_RECVPKTINFO, 1)
				}
				return nil
			})
		}
		switch network {
		case "udp4":
			return control.Raw(rawConn, func(fd uintptr) error {
				return unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_PKTINFO, 1)
			})
		default:
			return nil
		}
	}
}

type udpPacketWriter struct {
	inbound     *Inbound
	client      netip.AddrPort
	clientState *udpClientState
}

func (w *udpPacketWriter) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	defer buffer.Release()
	redirectAddress, loaded := w.clientState.redirectAddress(destination.AddrPort())
	if !loaded {
		return E.New("missing UDP redirect binding for ", destination)
	}
	var udpConn *net.UDPConn
	var controlMessage []byte
	if redirectAddress.Is4() {
		if w.inbound.listener4 == nil {
			return E.New("IPv4 eBPF listener is unavailable")
		}
		udpConn = w.inbound.listener4.UDPConn()
		controlMessage = (&ipv4.ControlMessage{Src: net.IP(redirectAddress.AsSlice())}).Marshal()
	} else {
		if w.inbound.listener6 == nil {
			return E.New("IPv6 eBPF listener is unavailable")
		}
		udpConn = w.inbound.listener6.UDPConn()
		controlMessage = (&ipv6.ControlMessage{Src: net.IP(redirectAddress.AsSlice())}).Marshal()
	}
	_, _, err := udpConn.WriteMsgUDPAddrPort(buffer.Bytes(), controlMessage, w.client)
	return err
}

func redirectAddressFromOOB(oob []byte) (netip.Addr, error) {
	var controlMessage4 ipv4.ControlMessage
	if err := controlMessage4.Parse(oob); err == nil {
		if address, loaded := netip.AddrFromSlice(controlMessage4.Dst); loaded && address.Is4() {
			return address.Unmap(), nil
		}
	}
	var controlMessage6 ipv6.ControlMessage
	if err := controlMessage6.Parse(oob); err == nil {
		if address, loaded := netip.AddrFromSlice(controlMessage6.Dst); loaded && address.Is6() && !address.Is4In6() {
			return address, nil
		}
	}
	return netip.Addr{}, E.New("IP packet info is missing")
}
