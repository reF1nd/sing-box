//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"net"
	"net/netip"
	"syscall"

	"github.com/sagernet/sing-box/adapter"
	commonEBPF "github.com/sagernet/sing-box/common/ebpf"
	"github.com/sagernet/sing-box/common/process"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"golang.org/x/sys/unix"
)

func (i *Inbound) newTCConnection(
	ctx context.Context,
	backend *commonEBPF.TCBackend,
	conn net.Conn,
	metadata adapter.InboundContext,
	onClose N.CloseHandlerFunc,
) {
	source := M.SocksaddrFromNet(conn.RemoteAddr()).AddrPort()
	destination := M.SocksaddrFromNet(conn.LocalAddr()).AddrPort()
	assignment, err := backend.LookupAssignment(commonEBPF.ProtocolTCP, source, destination, 0, true)
	if err != nil {
		i.tcpWarnings.errorContext(i.logger, ctx, "lookup TC eBPF TCP assignment: ", err)
		_ = conn.Close()
		return
	}
	metadata.Inbound = i.Tag()
	metadata.InboundType = i.Type()
	metadata.Source = M.SocksaddrFromNetIP(source)
	metadata.Destination = M.SocksaddrFromNetIP(destination)
	metadata.ProcessInfo = i.lookupProcessInfo(assignment.SocketCookie)
	if assignment.Path == commonEBPF.TCPathShared && assignment.SourceMACValid != 0 {
		metadata.SourceMACAddress = net.HardwareAddr(assignment.SourceMAC[:])
	}
	i.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}

func (i *Inbound) newTCPacket(
	backend *commonEBPF.TCBackend,
	buffer *buf.Buffer,
	oob []byte,
	source M.Socksaddr,
) {
	_, destination, interfaceIndex, err := packetDestinationsFromOOB(oob)
	if err != nil {
		i.udpWarnings.packetInfo.warn(i.logger, "read TC eBPF UDP destination: ", err)
		return
	}
	if !destination.IsValid() {
		i.udpWarnings.packetInfo.warn(i.logger, "TC eBPF UDP original destination is missing")
		return
	}
	client := source.AddrPort()
	assignment, err := backend.LookupAssignment(commonEBPF.ProtocolUDP, client, destination, interfaceIndex, false)
	if err != nil && interfaceIndex != 0 {
		assignment, err = backend.LookupAssignment(commonEBPF.ProtocolUDP, client, destination, 0, false)
	}
	if err != nil {
		i.udpWarnings.originalDestination.warn(i.logger, "lookup TC eBPF UDP assignment: ", err)
		return
	}
	var sourceMAC net.HardwareAddr
	if assignment.Path == commonEBPF.TCPathShared && assignment.SourceMACValid != 0 {
		sourceMAC = net.HardwareAddr(assignment.SourceMAC[:])
	}
	i.udpClientTable.setDirectBinding(client, destination, sourceMAC, assignment.SocketCookie)
	i.udpNat.NewPacket([][]byte{buffer.Bytes()}, source, M.SocksaddrFromNetIP(destination), nil)
}

func (i *Inbound) lookupProcessInfo(socketCookie uint64) *adapter.ConnectionOwner {
	if socketCookie == 0 || i.processTracker == nil {
		return nil
	}
	owner, err := i.processTracker.LookupOwner(socketCookie)
	if err != nil {
		i.logger.Trace("lookup eBPF socket process owner: ", err)
		return nil
	}
	processInfo, pathErr := process.FindProcessInfoByPID(
		owner.ProcessID,
		owner.UserID,
		i.networkManager.PackageManager(),
	)
	if pathErr != nil {
		i.logger.Trace("resolve eBPF socket process path: ", pathErr)
	}
	return processInfo
}

func (i *Inbound) prepareTCPacketConnection(
	source M.Socksaddr,
	_ M.Socksaddr,
) (bool, context.Context, N.PacketWriter, N.CloseHandlerFunc) {
	ctx := log.ContextWithNewID(i.ctx)
	client := source.AddrPort()
	clientState := i.udpClientTable.loadOrCreate(client)
	writer := &tcPacketWriter{inbound: i, client: client, clientState: clientState}
	return true, ctx, writer, func(error) {
		i.udpClientTable.delete(client, clientState)
	}
}

type tcPacketWriter struct {
	inbound     *Inbound
	client      netip.AddrPort
	clientState *udpClientState
}

func (w *tcPacketWriter) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	defer buffer.Release()
	destinationAddress := destination.AddrPort()
	_, loaded := w.clientState.redirectBinding(destinationAddress)
	if !loaded {
		if !w.clientState.hasAddressFamily(destinationAddress.Addr().Is4()) {
			return E.New("TC eBPF UDP reply alias limit reached or address family unavailable")
		}
		installed := w.inbound.udpClientTable.setDirectReplyBinding(
			w.client,
			w.clientState,
			destinationAddress,
		)
		if !installed {
			return E.New("TC eBPF UDP session closed or reply alias was rejected")
		}
		_, loaded = w.clientState.redirectBinding(destinationAddress)
		if !loaded {
			return E.New("TC eBPF UDP reply binding is unavailable")
		}
	}
	socket, err := w.inbound.udpReplySockets.get(destinationAddress, w.inbound.newTCUDPReplySocket)
	if err != nil {
		return err
	}
	_, err = socket.WriteToUDPAddrPort(buffer.Bytes(), w.client)
	return err
}

func (i *Inbound) newTCUDPReplySocket(source netip.AddrPort) (*net.UDPConn, error) {
	network := "udp6"
	if source.Addr().Is4() {
		network = "udp4"
	}
	listenConfig := net.ListenConfig{Control: func(_ string, _ string, rawConn syscall.RawConn) error {
		err := control.Raw(rawConn, func(fd uintptr) error {
			if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
				return err
			}
			if source.Addr().Is4() {
				return unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_TRANSPARENT, 1)
			}
			if err := unix.SetsockoptInt(int(fd), unix.SOL_IPV6, unix.IPV6_TRANSPARENT, 1); err != nil {
				return err
			}
			return unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_V6ONLY, 1)
		})
		if err != nil {
			return err
		}
		if provider, loaded := i.networkManager.(interface {
			EBPFSelfBypass() *commonEBPF.SelfBypass
		}); loaded {
			if tracker := provider.EBPFSelfBypass(); tracker != nil {
				return tracker.RegisterSocket(rawConn)
			}
		}
		return nil
	}}
	packetConnection, err := listenConfig.ListenPacket(i.ctx, network, source.String())
	if err != nil {
		return nil, E.Cause(err, "bind TC eBPF UDP reply socket to ", source)
	}
	udpConnection, loaded := packetConnection.(*net.UDPConn)
	if !loaded {
		_ = packetConnection.Close()
		return nil, E.New("TC eBPF UDP reply socket has unexpected type")
	}
	return udpConnection, nil
}
