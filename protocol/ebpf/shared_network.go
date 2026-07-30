//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/netlink"
	"github.com/sagernet/sing-box/adapter"
	ECommon "github.com/sagernet/sing-box/common/ebpf"
	"github.com/sagernet/sing-box/common/listener"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	udpnat "github.com/sagernet/sing/common/udpnat2"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

const (
	sharedNetworkRefresh = 3 * time.Second
	// Run before Android tethering offload (IPv6 priority 2, IPv4 priority 3).
	sharedNetworkTCPriority   = 1
	sharedIngressFilterHandle = 0x5342
	sharedEgressFilterHandle  = 0x5343
)

type sharedNetwork struct {
	parent      *Inbound
	interfaces  []string
	backend     *ECommon.SharedNetworkBackend
	tc          *sharedTCManager
	tcp4        *listener.Listener
	tcp6        *listener.Listener
	udp4        *listener.Listener
	udp6        *listener.Listener
	udpNat      *udpnat.Service
	udpClients  udpClientTable
	listenPort  uint16
	closeAccess sync.Mutex
}

func normalizeSharedNetworkOptions(options option.EBPFSharedNetworkOptions) (option.EBPFSharedNetworkOptions, error) {
	if !options.Enabled {
		return option.EBPFSharedNetworkOptions{}, nil
	}
	if len(options.IncludeInterface) == 0 {
		return option.EBPFSharedNetworkOptions{}, E.New("shared_network.include_interface must not be empty")
	}
	seen := make(map[string]struct{}, len(options.IncludeInterface))
	interfaces := make(badoption.Listable[string], 0, len(options.IncludeInterface))
	for _, interfaceName := range options.IncludeInterface {
		interfaceName = strings.TrimSpace(interfaceName)
		if interfaceName == "" {
			return option.EBPFSharedNetworkOptions{}, E.New("shared_network.include_interface contains an empty interface name")
		}
		if interfaceName == "lo" {
			return option.EBPFSharedNetworkOptions{}, E.New("shared_network.include_interface must not contain lo")
		}
		if _, loaded := seen[interfaceName]; loaded {
			continue
		}
		seen[interfaceName] = struct{}{}
		interfaces = append(interfaces, interfaceName)
	}
	options.IncludeInterface = interfaces
	return options, nil
}

func validateSharedNetworkProtocols(options option.EBPFSharedNetworkOptions, enableUDP bool, dnsMode string) error {
	if options.Enabled && dnsMode == dnsModeHijack && !enableUDP {
		return E.New("shared_network with dns_mode hijack requires UDP")
	}
	return nil
}

func newSharedNetwork(parent *Inbound, options option.EBPFSharedNetworkOptions) *sharedNetwork {
	shared := &sharedNetwork{
		parent:     parent,
		interfaces: append([]string(nil), options.IncludeInterface...),
	}
	udpTimeout := C.UDPTimeout
	if parent.listenOptions.UDPTimeout != 0 {
		udpTimeout = time.Duration(parent.listenOptions.UDPTimeout)
	}
	shared.udpNat = udpnat.New(shared, shared.preparePacketConnection, udpTimeout, false)
	return shared
}

func (s *sharedNetwork) Start(parentBackend *ECommon.Backend) error {
	if err := s.startListeners(); err != nil {
		return E.Errors(err, s.closeListeners())
	}
	backend, err := ECommon.PrepareSharedNetwork(
		parentBackend,
		s.listenPort,
		s.parent.enableTCP,
		s.parent.enableUDP,
		s.parent.redirectIPv4,
		s.parent.redirectIPv6,
	)
	if err != nil {
		return E.Errors(err, s.closeListeners())
	}
	s.backend = backend
	s.tc = &sharedTCManager{
		backend:     backend,
		logger:      s.parent.logger,
		interfaces:  s.interfaces,
		enableIPv4:  s.parent.redirectIPv4.IsValid(),
		attachments: make(map[string]*sharedTCAttachment),
	}
	if err = s.tc.Start(); err != nil {
		return E.Errors(err, s.Close())
	}
	s.parent.logger.Info(
		"eBPF shared-network ready: interfaces=[", s.tc.InterfaceString(),
		"], listen_port=", s.listenPort,
		", dns_mode=", s.parent.dnsMode,
		", tc_priority=", sharedNetworkTCPriority,
		", token_map_capacity=", ECommon.SharedNetworkMapCapacity,
		", programs=[tc/ingress, tc/egress]",
	)
	return nil
}

func (s *sharedNetwork) startListeners() error {
	type listenerSpec struct {
		network string
		ipv6    bool
		target  **listener.Listener
	}
	var specs []listenerSpec
	if s.parent.redirectIPv4.IsValid() {
		if s.parent.enableTCP {
			specs = append(specs, listenerSpec{N.NetworkTCP, false, &s.tcp4})
		}
		if s.parent.enableUDP {
			specs = append(specs, listenerSpec{N.NetworkUDP, false, &s.udp4})
		}
	}
	if s.parent.redirectIPv6.IsValid() {
		if s.parent.enableTCP {
			specs = append(specs, listenerSpec{N.NetworkTCP, true, &s.tcp6})
		}
		if s.parent.enableUDP {
			specs = append(specs, listenerSpec{N.NetworkUDP, true, &s.udp6})
		}
	}
	for _, spec := range specs {
		current := s.newListener(spec.network, spec.ipv6, s.listenPort)
		*spec.target = current
		if err := current.Start(); err != nil {
			return err
		}
		if s.listenPort == 0 {
			var address net.Addr
			if spec.network == N.NetworkTCP {
				address = current.TCPListener().Addr()
			} else {
				address = current.UDPConn().LocalAddr()
			}
			s.listenPort = M.SocksaddrFromNet(address).Port
			if s.listenPort == 0 {
				return E.New("shared-network listener selected an invalid port")
			}
		}
	}
	if s.listenPort == 0 {
		return E.New("shared-network has no enabled listener")
	}
	return nil
}

func (s *sharedNetwork) newListener(network string, ipv6Listener bool, port uint16) *listener.Listener {
	listenOptions := s.parent.listenOptions
	listenAddress := netip.IPv4Unspecified()
	if ipv6Listener {
		listenAddress = netip.IPv6Unspecified()
	}
	listenOptions.Listen = common.Ptr(badoption.Addr(listenAddress))
	listenOptions.ListenPort = port
	listenOptions.BindInterface = ""
	return listener.New(listener.Options{
		Context:             s.parent.ctx,
		Logger:              s.parent.logger,
		Network:             []string{network},
		Listen:              listenOptions,
		ConnectionHandler:   s,
		OOBPacketHandler:    s,
		DisablePacketOutput: true,
		SocketControl:       s.parent.socketControl(ipv6Listener),
	})
}

func (s *sharedNetwork) InterfaceUpdated() {
	s.udpNat.Purge()
	if s.tc != nil {
		s.tc.Wake()
	}
}

func (s *sharedNetwork) Close() error {
	if s == nil {
		return nil
	}
	s.closeAccess.Lock()
	defer s.closeAccess.Unlock()
	s.udpNat.Purge()
	if s.tc != nil {
		if err := s.tc.Close(); err != nil {
			return err
		}
		s.tc = nil
	}
	var backendErr error
	if s.backend != nil {
		backendErr = s.backend.Close()
		if s.backend.IsClosed() {
			s.backend = nil
		}
	}
	return E.Errors(backendErr, s.closeListeners())
}

func (s *sharedNetwork) closeListeners() error {
	listeners := []*listener.Listener{s.tcp4, s.tcp6, s.udp4, s.udp6}
	s.tcp4 = nil
	s.tcp6 = nil
	s.udp4 = nil
	s.udp6 = nil
	var closeErr error
	for _, current := range listeners {
		if current == nil {
			continue
		}
		closeErr = E.Errors(closeErr, common.Close(current))
	}
	return closeErr
}

func (s *sharedNetwork) IsClosed() bool {
	if s == nil {
		return true
	}
	s.closeAccess.Lock()
	defer s.closeAccess.Unlock()
	return s.tc == nil && s.backend == nil &&
		s.tcp4 == nil && s.tcp6 == nil && s.udp4 == nil && s.udp6 == nil
}

func (s *sharedNetwork) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	if s.backend == nil {
		conn.Close()
		return
	}
	client := M.SocksaddrFromNet(conn.RemoteAddr()).AddrPort()
	redirect := M.SocksaddrFromNet(conn.LocalAddr()).AddrPort()
	original, err := s.backend.LookupOriginal(ECommon.ProtocolTCP, client, redirect)
	if err != nil {
		s.parent.logger.ErrorContext(ctx, "lookup shared-network TCP original destination: ", err)
		conn.Close()
		return
	}
	metadata.Inbound = s.parent.Tag()
	metadata.InboundType = s.parent.Type()
	metadata.Source = M.SocksaddrFromNetIP(client)
	metadata.Destination = M.SocksaddrFromNetIP(original.Destination)
	s.parent.logger.InfoContext(ctx, "shared-network inbound connection to ", metadata.Destination)
	s.parent.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}

func (s *sharedNetwork) NewPacket(buffer *buf.Buffer, oob []byte, source M.Socksaddr) {
	if s.backend == nil {
		return
	}
	redirectAddress, err := redirectAddressFromOOB(oob)
	if err != nil {
		s.parent.logger.Warn("read shared-network UDP token address: ", err)
		return
	}
	client := source.AddrPort()
	redirect := netip.AddrPortFrom(redirectAddress, s.listenPort)
	original, err := s.backend.LookupOriginal(ECommon.ProtocolUDP, client, redirect)
	if err != nil {
		s.parent.logger.Warn("lookup shared-network UDP original destination: ", err)
		return
	}
	released := s.udpClients.setBinding(client, original.Destination, redirectAddress, false)
	s.deleteUDPRedirects(client, released)
	s.udpNat.NewPacket([][]byte{buffer.Bytes()}, source, M.SocksaddrFromNetIP(original.Destination), nil)
}

func (s *sharedNetwork) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	metadata := adapter.InboundContext{
		Inbound:     s.parent.Tag(),
		InboundType: s.parent.Type(),
		Source:      source,
		Destination: destination,
	}
	//nolint:staticcheck
	metadata.InboundDetour = s.parent.listenOptions.Detour
	s.parent.logger.InfoContext(ctx, "shared-network inbound packet connection to ", destination)
	s.parent.router.RoutePacketConnectionEx(ctx, conn, metadata, onClose)
}

func (s *sharedNetwork) preparePacketConnection(source M.Socksaddr, destination M.Socksaddr, _ any) (bool, context.Context, N.PacketWriter, N.CloseHandlerFunc) {
	ctx := log.ContextWithNewID(s.parent.ctx)
	client := source.AddrPort()
	clientState := s.udpClients.loadOrCreate(client)
	writer := &sharedPacketWriter{
		shared:      s,
		client:      client,
		clientState: clientState,
	}
	return true, ctx, writer, func(error) {
		s.deleteUDPRedirects(client, s.udpClients.delete(client, clientState))
	}
}

func (s *sharedNetwork) deleteUDPRedirects(client netip.AddrPort, redirects []netip.Addr) {
	if s.backend == nil {
		return
	}
	for _, address := range redirects {
		redirect := netip.AddrPortFrom(address, s.listenPort)
		if err := s.backend.DeleteRedirect(ECommon.ProtocolUDP, client, redirect); err != nil {
			s.parent.logger.Warn("delete shared-network UDP redirect mapping for ", redirect, ": ", err)
		}
	}
}

type sharedPacketWriter struct {
	shared      *sharedNetwork
	client      netip.AddrPort
	clientState *udpClientState
}

func (w *sharedPacketWriter) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	defer buffer.Release()
	redirectAddress, loaded := w.clientState.redirectAddress(destination.AddrPort())
	if !loaded {
		return E.New("missing shared-network UDP token for ", destination)
	}
	var udpConn *net.UDPConn
	var controlMessage []byte
	if redirectAddress.Is4() {
		if w.shared.udp4 == nil {
			return E.New("shared-network IPv4 UDP listener is unavailable")
		}
		udpConn = w.shared.udp4.UDPConn()
		controlMessage = (&ipv4.ControlMessage{Src: net.IP(redirectAddress.AsSlice())}).Marshal()
	} else {
		if w.shared.udp6 == nil {
			return E.New("shared-network IPv6 UDP listener is unavailable")
		}
		udpConn = w.shared.udp6.UDPConn()
		controlMessage = (&ipv6.ControlMessage{Src: net.IP(redirectAddress.AsSlice())}).Marshal()
	}
	_, _, err := udpConn.WriteMsgUDPAddrPort(buffer.Bytes(), controlMessage, w.client)
	return err
}

type sharedTCManager struct {
	backend     *ECommon.SharedNetworkBackend
	logger      interfaceLogger
	interfaces  []string
	enableIPv4  bool
	access      sync.Mutex
	attachments map[string]*sharedTCAttachment
	enabled     bool
	cancel      context.CancelFunc
	done        chan struct{}
	wake        chan struct{}
}

type interfaceLogger interface {
	Info(args ...any)
	Warn(args ...any)
}

type sharedTCAttachment struct {
	interfaceName        string
	ifindex              int
	ingress              *netlink.BpfFilter
	egress               *netlink.BpfFilter
	restoreRouteLocalnet bool
}

func (m *sharedTCManager) Start() error {
	if err := m.reconcile(); err != nil {
		return E.Errors(err, m.closeAttachments())
	}
	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel
	m.done = make(chan struct{})
	m.wake = make(chan struct{}, 1)
	go m.loop(ctx)
	return nil
}

func (m *sharedTCManager) loop(ctx context.Context) {
	defer close(m.done)
	ticker := time.NewTicker(sharedNetworkRefresh)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-m.wake:
		}
		if err := m.reconcile(); err != nil {
			m.logger.Warn("refresh eBPF shared-network interfaces: ", err)
		}
	}
}

func (m *sharedTCManager) Wake() {
	if m == nil || m.wake == nil {
		return
	}
	select {
	case m.wake <- struct{}{}:
	default:
	}
}

func (m *sharedTCManager) reconcile() error {
	hostAddresses, err := sharedHostAddresses()
	if err != nil {
		return err
	}
	if err = m.backend.UpdateHostAddresses(hostAddresses); err != nil {
		return err
	}
	desired := make(map[string]netlink.Link, len(m.interfaces))
	for _, interfaceName := range m.interfaces {
		link, linkErr := netlink.LinkByName(interfaceName)
		if isSharedNetworkLinkNotFound(linkErr) {
			continue
		}
		if linkErr != nil {
			return E.Cause(linkErr, "find shared-network interface ", interfaceName)
		}
		if linkErr = validateSharedNetworkLink(link); linkErr != nil {
			return linkErr
		}
		desired[interfaceName] = link
	}

	m.access.Lock()
	defer m.access.Unlock()
	for interfaceName, attachment := range m.attachments {
		link, loaded := desired[interfaceName]
		if loaded && link.Attrs().Index == attachment.ifindex {
			continue
		}
		if err = m.detachLocked(attachment); err != nil {
			return E.Cause(err, "detach stale shared-network interface ", interfaceName)
		}
		delete(m.attachments, interfaceName)
		m.logger.Info("eBPF shared-network detached from ", interfaceName)
	}
	for interfaceName, link := range desired {
		if _, loaded := m.attachments[interfaceName]; loaded {
			continue
		}
		attachment, attachErr := attachSharedTC(link, m.backend, m.enableIPv4)
		if attachErr != nil {
			return E.Cause(attachErr, "attach eBPF shared-network to ", interfaceName)
		}
		m.attachments[interfaceName] = attachment
		m.logger.Info("eBPF shared-network attached to ", interfaceName, " (ifindex=", link.Attrs().Index, ")")
	}
	return m.updateEnabledLocked(len(m.attachments) > 0)
}

func isSharedNetworkLinkNotFound(err error) bool {
	if errors.Is(err, unix.ENODEV) || errors.Is(err, unix.ENOENT) {
		return true
	}
	var linkNotFoundError netlink.LinkNotFoundError
	return errors.As(err, &linkNotFoundError)
}

func validateSharedNetworkLink(link netlink.Link) error {
	if link == nil || link.Attrs() == nil {
		return E.New("invalid shared-network interface")
	}
	if len(link.Attrs().HardwareAddr) != 6 {
		return E.New("shared-network interface ", link.Attrs().Name, " is not Ethernet-like")
	}
	return nil
}

func (m *sharedTCManager) updateEnabledLocked(enabled bool) error {
	if m.enabled == enabled {
		return nil
	}
	var err error
	if enabled {
		err = m.backend.Enable()
	} else {
		err = m.backend.Disable()
	}
	if err == nil {
		m.enabled = enabled
	}
	return err
}

func (m *sharedTCManager) detachLocked(attachment *sharedTCAttachment) error {
	detachErr := E.Errors(
		detachSharedTCFilter(attachment.ingress),
		detachSharedTCFilter(attachment.egress),
	)
	if detachErr != nil {
		return detachErr
	}
	if attachment.restoreRouteLocalnet {
		return restoreSharedRouteLocalnet(attachment.interfaceName)
	}
	return nil
}

func (m *sharedTCManager) InterfaceString() string {
	m.access.Lock()
	defer m.access.Unlock()
	names := make([]string, 0, len(m.attachments))
	for name := range m.attachments {
		names = append(names, name)
	}
	sort.Strings(names)
	if len(names) == 0 {
		return "waiting for " + strings.Join(m.interfaces, ", ")
	}
	return strings.Join(names, ", ")
}

func (m *sharedTCManager) Close() error {
	if m == nil {
		return nil
	}
	if m.cancel != nil {
		m.cancel()
		<-m.done
		m.cancel = nil
	}
	return m.closeAttachments()
}

func (m *sharedTCManager) closeAttachments() error {
	m.access.Lock()
	defer m.access.Unlock()
	var closeErr error
	if err := m.updateEnabledLocked(false); err != nil {
		closeErr = err
	}
	for name, attachment := range m.attachments {
		if err := m.detachLocked(attachment); err != nil {
			closeErr = E.Errors(closeErr, E.Cause(err, "detach shared-network interface ", name))
			continue
		}
		delete(m.attachments, name)
	}
	return closeErr
}

func attachSharedTC(link netlink.Link, backend *ECommon.SharedNetworkBackend, enableIPv4 bool) (*sharedTCAttachment, error) {
	restoreRouteLocalnet := false
	if enableIPv4 {
		var err error
		restoreRouteLocalnet, err = enableSharedRouteLocalnet(link.Attrs().Name)
		if err != nil {
			return nil, err
		}
	}
	if err := ensureClsact(link); err != nil {
		if restoreRouteLocalnet {
			_ = restoreSharedRouteLocalnet(link.Attrs().Name)
		}
		return nil, err
	}
	egress, err := attachSharedTCFilter(
		link,
		netlink.HANDLE_MIN_EGRESS,
		backend.EgressProgramFD(),
		"sb_share_out",
		sharedEgressFilterHandle,
	)
	if err != nil {
		if restoreRouteLocalnet {
			_ = restoreSharedRouteLocalnet(link.Attrs().Name)
		}
		return nil, err
	}
	ingress, err := attachSharedTCFilter(
		link,
		netlink.HANDLE_MIN_INGRESS,
		backend.IngressProgramFD(),
		"sb_share_in",
		sharedIngressFilterHandle,
	)
	if err != nil {
		var routeErr error
		if restoreRouteLocalnet {
			routeErr = restoreSharedRouteLocalnet(link.Attrs().Name)
		}
		return nil, E.Errors(err, detachSharedTCFilter(egress), routeErr)
	}
	return &sharedTCAttachment{
		interfaceName:        link.Attrs().Name,
		ifindex:              link.Attrs().Index,
		ingress:              ingress,
		egress:               egress,
		restoreRouteLocalnet: restoreRouteLocalnet,
	}, nil
}

func sharedRouteLocalnetPath(interfaceName string) string {
	return "/proc/sys/net/ipv4/conf/" + interfaceName + "/route_localnet"
}

func enableSharedRouteLocalnet(interfaceName string) (bool, error) {
	path := sharedRouteLocalnetPath(interfaceName)
	value, err := os.ReadFile(path)
	if err != nil {
		return false, E.Cause(err, "read route_localnet for ", interfaceName)
	}
	if strings.TrimSpace(string(value)) == "1" {
		return false, nil
	}
	if strings.TrimSpace(string(value)) != "0" {
		return false, E.New("unexpected route_localnet value for ", interfaceName)
	}
	if err = os.WriteFile(path, []byte("1"), 0o644); err != nil {
		return false, E.Cause(err, "enable route_localnet for ", interfaceName)
	}
	return true, nil
}

func restoreSharedRouteLocalnet(interfaceName string) error {
	path := sharedRouteLocalnetPath(interfaceName)
	value, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return E.Cause(err, "read route_localnet for ", interfaceName)
	}
	if strings.TrimSpace(string(value)) != "1" {
		return nil
	}
	if err = os.WriteFile(path, []byte("0"), 0o644); err != nil {
		return E.Cause(err, "restore route_localnet for ", interfaceName)
	}
	return nil
}

func attachSharedTCFilter(link netlink.Link, parent uint32, programFD int, programName string, handle uint16) (*netlink.BpfFilter, error) {
	if programFD < 0 {
		return nil, E.New("shared-network eBPF program is unavailable")
	}
	filters, err := netlink.FilterList(link, parent)
	if err != nil {
		return nil, err
	}
	filterHandle := netlink.MakeHandle(0, handle)
	for _, existing := range filters {
		bpfFilter, isBPF := existing.(*netlink.BpfFilter)
		if isBPF && bpfFilter.Name == programName {
			if err = netlink.FilterDel(existing); err != nil && !errors.Is(err, unix.ENOENT) {
				return nil, err
			}
			continue
		}
		if existing.Attrs().Handle == filterHandle {
			return nil, E.New("TC filter handle conflict on ", link.Attrs().Name)
		}
	}
	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    parent,
			Handle:    filterHandle,
			Priority:  sharedNetworkTCPriority,
			Protocol:  unix.ETH_P_ALL,
		},
		Fd:           programFD,
		Name:         programName,
		DirectAction: true,
	}
	if err = netlink.FilterAdd(filter); err != nil {
		return nil, err
	}
	return filter, nil
}

func detachSharedTCFilter(filter *netlink.BpfFilter) error {
	if filter == nil {
		return nil
	}
	err := netlink.FilterDel(filter)
	if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENODEV) || errors.Is(err, unix.ESRCH) {
		return nil
	}
	return err
}

func ensureClsact(link netlink.Link) error {
	qdiscs, err := netlink.QdiscList(link)
	if err != nil {
		return err
	}
	for _, qdisc := range qdiscs {
		if qdisc.Type() == "clsact" {
			return nil
		}
	}
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	if err = netlink.QdiscAdd(qdisc); err != nil && !errors.Is(err, unix.EEXIST) {
		return err
	}
	return nil
}

func sharedHostAddresses() ([]netip.Addr, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, E.Cause(err, "list interfaces for shared-network host bypass")
	}
	var addresses []netip.Addr
	for _, networkInterface := range interfaces {
		interfaceAddresses, addressErr := networkInterface.Addrs()
		if addressErr != nil {
			return nil, E.Cause(addressErr, "list addresses for interface ", networkInterface.Name)
		}
		for _, interfaceAddress := range interfaceAddresses {
			prefix, parseErr := netip.ParsePrefix(interfaceAddress.String())
			if parseErr == nil {
				addresses = append(addresses, prefix.Addr().Unmap())
			}
		}
	}
	return addresses, nil
}
