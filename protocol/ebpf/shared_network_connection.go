//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"net"
	"net/netip"

	"github.com/sagernet/sing-box/adapter"
	ECommon "github.com/sagernet/sing-box/common/ebpf"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func (s *sharedNetwork) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	backend := s.sharedBackendInstance()
	if backend == nil {
		conn.Close()
		return
	}
	client := M.SocksaddrFromNet(conn.RemoteAddr()).AddrPort()
	tokenDestination := M.SocksaddrFromNet(conn.LocalAddr()).AddrPort()
	original, flow, err := backend.LookupFlow(ECommon.ProtocolTCP, client, tokenDestination)
	if err != nil {
		s.inbound.logger.ErrorContext(ctx, "lookup shared-network TCP original destination: ", err)
		conn.Close()
		return
	}
	metadata.Inbound = s.inbound.Tag()
	metadata.InboundType = s.inbound.Type()
	metadata.Source = M.SocksaddrFromNetIP(client)
	metadata.Destination = M.SocksaddrFromNetIP(original.Destination)
	onClose = N.AppendClose(onClose, func(error) {
		s.releaseFlow(flow)
	})
	s.inbound.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}

func (s *sharedNetwork) NewPacket(buffer *buf.Buffer, oob []byte, source M.Socksaddr) {
	backend := s.sharedBackendInstance()
	if backend == nil {
		return
	}
	tokenAddress, err := redirectAddressFromOOB(oob)
	if err != nil {
		s.udpWarnings.packetInfo.warn(s.inbound.logger, "read shared-network UDP token address: ", err)
		return
	}
	client := source.AddrPort()
	tokenDestination := netip.AddrPortFrom(tokenAddress, s.listeners.selectedPort())
	cached, bindingReady, loaded := s.udpClientTable.cachedPacketState(client, tokenAddress)
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
		released, installed := s.udpClientTable.setSharedBinding(client, original.Destination, tokenAddress, flow)
		if retainedFlow && !installed {
			s.releaseFlow(flow)
		}
		s.releaseFlows(released)
	}
	s.udpNat.NewPacket([][]byte{buffer.Bytes()}, source, M.SocksaddrFromNetIP(original.Destination), nil)
}

func (s *sharedNetwork) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	metadata := adapter.InboundContext{
		Inbound:     s.inbound.Tag(),
		InboundType: s.inbound.Type(),
		Source:      source,
		Destination: destination,
	}
	s.inbound.router.RoutePacketConnectionEx(ctx, conn, metadata, onClose)
}

func (s *sharedNetwork) preparePacketConnection(source M.Socksaddr, destination M.Socksaddr, _ any) (bool, context.Context, N.PacketWriter, N.CloseHandlerFunc) {
	ctx := log.ContextWithNewID(s.inbound.ctx)
	client := source.AddrPort()
	clientState := s.udpClientTable.loadOrCreate(client)
	writer := &sharedPacketWriter{
		sharedNetwork: s,
		client:        client,
		clientState:   clientState,
	}
	return true, ctx, writer, func(error) {
		s.releaseFlows(s.udpClientTable.deleteShared(client, clientState))
	}
}

func (s *sharedNetwork) releaseFlows(releases []udpRedirectRelease) {
	for _, release := range releases {
		s.releaseFlow(release.sharedFlow)
	}
}

func (s *sharedNetwork) releaseFlow(flow *ECommon.SharedNetworkFlowHandle) {
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
	sharedNetwork *sharedNetwork
	client        netip.AddrPort
	clientState   *udpClientState
}

func (w *sharedPacketWriter) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	defer buffer.Release()
	w.sharedNetwork.lifecycleAccess.RLock()
	defer w.sharedNetwork.lifecycleAccess.RUnlock()
	binding, loaded := w.clientState.redirectBinding(destination.AddrPort())
	if !loaded {
		return E.New("missing shared-network UDP token for ", destination)
	}
	return w.sharedNetwork.listeners.writeUDP(buffer.Bytes(), binding.packetInfo, w.client, binding.address)
}
