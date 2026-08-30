//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"

	"github.com/sagernet/sing-box/adapter"
	ECommon "github.com/sagernet/sing-box/common/ebpf"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"golang.org/x/sys/unix"
)

func (s *sharedRewrite) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	backend := s.sharedBackendInstance()
	if backend == nil {
		conn.Close()
		return
	}
	client := M.SocksaddrFromNet(conn.RemoteAddr()).AddrPort()
	tokenDestination := M.SocksaddrFromNet(conn.LocalAddr()).AddrPort()
	original, flow, err := backend.LookupFlow(ECommon.ProtocolTCP, client, tokenDestination)
	if errors.Is(err, unix.ENOENT) {
		s.logMissingSharedTCPRedirect(ctx, client, tokenDestination)
		conn.Close()
		return
	}
	if err != nil {
		s.tcpWarnings.errorContext(
			s.inbound.logger,
			ctx,
			"lookup shared-network TCP original destination: ", err,
		)
		conn.Close()
		return
	}
	metadata.Inbound = s.inbound.Tag()
	metadata.InboundType = s.inbound.Type()
	metadata.Source = M.SocksaddrFromNetIP(client)
	metadata.Destination = M.SocksaddrFromNetIP(original.Destination)
	metadata.SourceMACAddress = original.SourceMAC
	onClose = N.AppendClose(onClose, func(error) {
		s.releaseFlow(flow)
	})
	s.inbound.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}

func (s *sharedRewrite) logMissingSharedTCPRedirect(
	ctx context.Context,
	client netip.AddrPort,
	listener netip.AddrPort,
) {
	if listener.Port() != s.listeners.selectedPort() || !s.inbound.isCgroupRedirectAddress(listener.Addr()) {
		return
	}
	allowed, suppressed := s.tcpWarnings.allow(time.Now())
	if !allowed {
		return
	}
	args := []any{
		"missing shared-network TCP redirect state",
		": client=", client,
		" listener=", listener,
	}
	if suppressed > 0 {
		args = append(args, " (", suppressed, " similar errors suppressed)")
	}
	s.inbound.logger.ErrorContext(ctx, args...)
}

func (s *sharedRewrite) NewPacket(buffer *buf.Buffer, oob []byte, source M.Socksaddr) {
	backend := s.sharedBackendInstance()
	if backend == nil {
		return
	}
	tokenAddress, _, _, err := packetDestinationsFromOOB(oob)
	if err != nil {
		s.udpWarnings.packetInfo.warn(s.inbound.logger, "read shared-network UDP token address: ", err)
		return
	}
	client := source.AddrPort()
	tokenDestination := netip.AddrPortFrom(tokenAddress, s.listeners.selectedPort())
	cached, bindingReady, loaded := s.sharedUDPClientTable.cachedPacketState(client, tokenAddress)
	original := cached.original
	flow := cached.sharedFlow
	retainedFlow := false
	if !loaded {
		original, flow, err = backend.LookupFlow(ECommon.ProtocolUDP, client, tokenDestination)
		if err != nil {
			s.udpWarnings.originalDestination.warn(s.inbound.logger, "lookup shared-network UDP original destination: ", err)
			return
		}
		retainedFlow = true
	}
	if !bindingReady {
		released, installed := s.sharedUDPClientTable.setSharedBinding(client, original, tokenAddress, flow)
		if retainedFlow && !installed {
			s.releaseFlow(flow)
		}
		s.releaseFlows(released)
	}
	s.udpNat.NewPacket([][]byte{buffer.Bytes()}, source, M.SocksaddrFromNetIP(original.Destination), nil)
}

func (s *sharedRewrite) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	metadata := adapter.InboundContext{
		Inbound:     s.inbound.Tag(),
		InboundType: s.inbound.Type(),
		Source:      source,
		Destination: destination,
	}
	if clientState, loaded := s.sharedUDPClientTable.load(source.AddrPort()); loaded {
		metadata.SourceMACAddress = clientState.sourceMACAddress()
	}
	s.inbound.router.RoutePacketConnectionEx(ctx, conn, metadata, onClose)
}

func (s *sharedRewrite) preparePacketConnection(source M.Socksaddr, destination M.Socksaddr, _ any) (bool, context.Context, N.PacketWriter, N.CloseHandlerFunc) {
	ctx := log.ContextWithNewID(s.inbound.ctx)
	client := source.AddrPort()
	clientState := s.sharedUDPClientTable.loadOrCreate(client)
	writer := &sharedPacketWriter{
		sharedRewrite: s,
		client:        client,
		clientState:   clientState,
	}
	return true, ctx, writer, func(error) {
		s.releaseFlows(s.sharedUDPClientTable.deleteShared(client, clientState))
	}
}

func (s *sharedRewrite) releaseFlows(releases []sharedUDPRedirectRelease) {
	for _, release := range releases {
		s.releaseFlow(release.sharedFlow)
	}
}

func (s *sharedRewrite) releaseFlow(flow *ECommon.SharedNetworkFlowHandle) {
	if flow == nil {
		return
	}
	backend := s.sharedBackendInstance()
	if backend == nil {
		return
	}
	if err := backend.ReleaseFlow(flow); err != nil {
		s.udpWarnings.cleanup.warn(s.inbound.logger, "release shared-network flow: ", err)
	}
}

type sharedPacketWriter struct {
	sharedRewrite *sharedRewrite
	client        netip.AddrPort
	clientState   *sharedUDPClientState
}

func (w *sharedPacketWriter) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	defer buffer.Release()
	w.sharedRewrite.lifecycleAccess.RLock()
	defer w.sharedRewrite.lifecycleAccess.RUnlock()
	destinationAddress := destination.AddrPort()
	binding, loaded := w.clientState.redirectBinding(destinationAddress)
	if !loaded {
		var err error
		binding, err = w.reserveReplyBinding(destinationAddress)
		if err != nil {
			return E.Cause(err, "recover missing shared-network UDP token for ", destination)
		}
	}
	return w.sharedRewrite.listeners.writeUDP(buffer.Bytes(), binding.packetInfo, w.client, binding.address)
}

func (w *sharedPacketWriter) reserveReplyBinding(destination netip.AddrPort) (sharedUDPRedirectBinding, error) {
	template, loaded := w.clientState.replyTemplate(destination, true)
	if !loaded {
		template, loaded = w.clientState.replyTemplate(destination, false)
	}
	if !loaded {
		return sharedUDPRedirectBinding{}, E.New("shared-network UDP reply alias limit reached or base flow unavailable")
	}
	backend := w.sharedRewrite.sharedBackendInstance()
	if backend == nil {
		return sharedUDPRedirectBinding{}, E.New("shared-network eBPF backend is closed")
	}
	sourceMAC := w.clientState.sourceMACAddress()
	redirectAddress, flow, err := backend.ReserveUDPReplyFlow(template.sharedFlow, destination, sourceMAC)
	if err != nil {
		return sharedUDPRedirectBinding{}, err
	}
	released, installed := w.sharedRewrite.sharedUDPClientTable.setSharedReplyBinding(
		w.client,
		w.clientState,
		ECommon.OriginalDestination{Destination: destination, SourceMAC: sourceMAC},
		redirectAddress,
		flow,
	)
	if !installed {
		released = append(released, sharedUDPRedirectRelease{sharedFlow: flow})
	}
	w.sharedRewrite.releaseFlows(released)
	if binding, loaded := w.clientState.redirectBinding(destination); loaded {
		return binding, nil
	}
	return sharedUDPRedirectBinding{}, E.New("shared-network UDP session closed or reply alias was rejected")
}
