//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"syscall"

	commonEBPF "github.com/CHIZI-0618/sing-ebpf"
	"github.com/sagernet/sing-box/adapter"
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
		i.counters.assignmentLookupFailures.Add(1)
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
	takeOwnership bool,
) bool {
	_, destination, interfaceIndex, err := packetDestinationsFromOOB(oob)
	if err != nil {
		i.udpWarnings.packetInfo.warn(i.logger, "read TC eBPF UDP destination: ", err)
		return false
	}
	if !destination.IsValid() {
		i.udpWarnings.packetInfo.warn(i.logger, "TC eBPF UDP original destination is missing")
		return false
	}
	client := source.AddrPort()
	assignment, err := backend.LookupAssignment(commonEBPF.ProtocolUDP, client, destination, interfaceIndex, false)
	if err != nil && interfaceIndex != 0 {
		assignment, err = backend.LookupAssignment(commonEBPF.ProtocolUDP, client, destination, 0, false)
	}
	if err != nil {
		i.counters.assignmentLookupFailures.Add(1)
		i.udpWarnings.originalDestination.warn(i.logger, "lookup TC eBPF UDP assignment: ", err)
		return false
	}
	var sourceMAC net.HardwareAddr
	if assignment.Path == commonEBPF.TCPathShared && assignment.SourceMACValid != 0 {
		sourceMAC = net.HardwareAddr(assignment.SourceMAC[:])
	}
	scope := udpSessionScopeLocalTC
	if assignment.Path == commonEBPF.TCPathShared {
		scope = udpSessionScopeSharedTC
	}
	key := udpSessionKey{
		Source:         client,
		Scope:          scope,
		SocketCookie:   assignment.SocketCookie,
		InterfaceIndex: assignment.InterfaceIndex,
	}
	i.udpClientTable.setDirectBinding(key, destination, sourceMAC, assignment.SocketCookie)
	if takeOwnership {
		i.udpNat.NewPacketBuffer(key, buffer, source, M.SocksaddrFromNetIP(destination), nil)
		return true
	}
	i.udpNat.NewPacket(key, [][]byte{buffer.Bytes()}, source, M.SocksaddrFromNetIP(destination), nil)
	return false
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
	cacheKey := processInfoCacheKey{processID: owner.ProcessID, userID: owner.UserID}
	processInfo, pathErr, resolved := i.processInfoCache.loadOrResolve(cacheKey, func() (*adapter.ConnectionOwner, error) {
		return process.FindProcessInfoByPID(
			owner.ProcessID,
			owner.UserID,
			i.networkManager.PackageManager(),
		)
	})
	if resolved && pathErr != nil {
		i.logger.Trace("resolve eBPF socket process path: ", pathErr)
	}
	return processInfo
}

func (i *Inbound) prepareTCPacketConnection(
	_ M.Socksaddr,
	_ M.Socksaddr,
	key udpSessionKey,
) (bool, context.Context, N.PacketWriter, N.CloseHandlerFunc) {
	ctx := log.ContextWithNewID(i.ctx)
	clientState := i.udpClientTable.loadOrCreate(key)
	writer := &tcPacketWriter{inbound: i, key: key, clientState: clientState}
	return true, ctx, writer, func(error) {
		i.deleteCgroupUDPRedirects(i.udpClientTable.delete(key, clientState))
	}
}

type tcPacketWriter struct {
	inbound        *Inbound
	key            udpSessionKey
	clientState    *udpClientState
	newReplySocket func(netip.AddrPort) (*net.UDPConn, error)
}

func (w *tcPacketWriter) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	defer buffer.Release()
	destinationAddress := destination.AddrPort()
	binding, err := w.ensureReplyBinding(destinationAddress)
	if err != nil {
		return err
	}
	if w.clientState.isCgroupDataPlane() {
		return w.inbound.listeners.writeUDP(buffer.Bytes(), binding.packetInfo, w.key.Source, binding.redirectAddress)
	}
	entry, release, err := w.inbound.udpReplySockets.get(destinationAddress, w.replySocketFactory())
	if err != nil {
		w.logReplySocketError(err)
		return err
	}
	defer release()
	_, err = entry.conn.WriteToUDPAddrPort(buffer.Bytes(), w.key.Source)
	return err
}

func (w *tcPacketWriter) ensureReplyBinding(destinationAddress netip.AddrPort) (udpRedirectBinding, error) {
	binding, loaded := w.clientState.redirectBinding(destinationAddress)
	if !loaded {
		if w.clientState.isCgroupDataPlane() {
			backend := w.inbound.cgroupBackendInstance()
			if backend == nil {
				return udpRedirectBinding{}, E.New("cgroup eBPF backend is closed")
			}
			redirectAddress, err := backend.ReserveUDPReplyRedirect(destinationAddress, w.inbound.listeners.selectedPort())
			if err != nil {
				return udpRedirectBinding{}, err
			}
			if !w.inbound.udpClientTable.setCgroupReplyBinding(w.key, w.clientState, destinationAddress, redirectAddress) {
				_ = backend.DeleteRedirect(
					commonEBPF.ProtocolUDP,
					netip.AddrPortFrom(redirectAddress, w.inbound.listeners.selectedPort()),
				)
				return udpRedirectBinding{}, E.New("cgroup eBPF UDP reply binding was rejected")
			}
			binding, loaded = w.clientState.redirectBinding(destinationAddress)
			if !loaded {
				return udpRedirectBinding{}, E.New("cgroup eBPF UDP reply binding is unavailable")
			}
		}
	}
	if !loaded {
		if !w.clientState.hasAddressFamily(destinationAddress.Addr().Is4()) {
			return udpRedirectBinding{}, E.New("TC eBPF UDP reply alias limit reached or address family unavailable")
		}
		installed := w.inbound.udpClientTable.setDirectReplyBinding(
			w.key,
			w.clientState,
			destinationAddress,
		)
		if !installed {
			return udpRedirectBinding{}, E.New("TC eBPF UDP session closed or reply alias was rejected")
		}
		binding, loaded = w.clientState.redirectBinding(destinationAddress)
		if !loaded {
			return udpRedirectBinding{}, E.New("TC eBPF UDP reply binding is unavailable")
		}
	}
	return binding, nil
}

func (w *tcPacketWriter) WritePacketBatch(buffers []*buf.Buffer, destinations []M.Socksaddr) error {
	if len(buffers) == 0 || len(buffers) != len(destinations) {
		buf.ReleaseMulti(buffers)
		return os.ErrInvalid
	}
	if w.clientState.isCgroupDataPlane() {
		packetInfos := make([][]byte, len(buffers))
		sources := make([]netip.Addr, len(buffers))
		for index, destination := range destinations {
			binding, err := w.ensureReplyBinding(destination.AddrPort())
			if err != nil {
				buf.ReleaseMulti(buffers)
				return err
			}
			packetInfos[index] = binding.packetInfo
			sources[index] = binding.redirectAddress
		}
		return w.inbound.listeners.writeUDPBatch(buffers, packetInfos, w.key.Source, sources)
	}
	type packetGroup struct {
		buffers      []*buf.Buffer
		destinations []M.Socksaddr
	}
	groups := make(map[netip.AddrPort]*packetGroup)
	client := M.SocksaddrFromNetIP(w.key.Source)
	for index, destination := range destinations {
		destinationAddress := destination.AddrPort()
		if _, err := w.ensureReplyBinding(destinationAddress); err != nil {
			buf.ReleaseMulti(buffers)
			return err
		}
		group := groups[destinationAddress]
		if group == nil {
			group = &packetGroup{}
			groups[destinationAddress] = group
		}
		group.buffers = append(group.buffers, buffers[index])
		group.destinations = append(group.destinations, client)
	}
	var batchErr error
	for source, group := range groups {
		entry, release, err := w.inbound.udpReplySockets.get(source, w.replySocketFactory())
		if err != nil {
			w.logReplySocketError(err)
			buf.ReleaseMulti(group.buffers)
			batchErr = errors.Join(batchErr, err)
			continue
		}
		err = entry.writer.WritePacketBatch(group.buffers, group.destinations)
		release()
		batchErr = errors.Join(batchErr, err)
	}
	return batchErr
}

func (w *tcPacketWriter) logReplySocketError(err error) {
	if errors.Is(err, errUDPReplySocketCapacity) {
		w.inbound.udpWarnings.replySocketCapacity.warn(
			w.inbound.logger,
			"UDP eBPF reply socket pool reached its global capacity; all sockets are currently in use",
		)
	}
}

func (w *tcPacketWriter) replySocketFactory() func(netip.AddrPort) (*net.UDPConn, error) {
	if w.newReplySocket != nil {
		return w.newReplySocket
	}
	return w.inbound.newTCUDPReplySocket
}

var _ N.PacketBatchWriter = (*tcPacketWriter)(nil)

func (i *Inbound) deleteCgroupUDPRedirects(addresses []netip.Addr) {
	backend := i.cgroupBackendInstance()
	if backend == nil {
		return
	}
	for _, address := range addresses {
		destination := netip.AddrPortFrom(address, i.listeners.selectedPort())
		if err := backend.DeleteRedirect(commonEBPF.ProtocolUDP, destination); err != nil && !errors.Is(err, unix.ENOENT) {
			i.udpWarnings.cleanup.warn(i.logger, "delete cgroup eBPF UDP redirect: ", err)
		}
	}
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
