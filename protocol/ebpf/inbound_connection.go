//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"syscall"
	"time"

	"github.com/sagernet/sing-box/adapter"
	ECommon "github.com/sagernet/sing-box/common/ebpf"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"golang.org/x/sys/unix"
)

func (i *Inbound) startListeners() error {
	err := i.listeners.start(
		i.enableTCP,
		i.enableUDP,
		i.redirectIPv4Prefix.IsValid(),
		i.cgroupIPv6Enabled(),
		i.newListener,
	)
	if err == nil {
		i.logger.Debug("eBPF local cgroup redirect listeners ready: [", i.listeners.String(), "]")
	}
	return err
}

func (i *Inbound) closeListeners() error {
	return i.listeners.close()
}

func (i *Inbound) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	backend := i.cgroupBackendInstance()
	if backend == nil {
		conn.Close()
		return
	}
	listenerDestination := M.SocksaddrFromNet(conn.LocalAddr()).AddrPort()
	original, err := backend.TakeOriginal(ECommon.ProtocolTCP, listenerDestination)
	if errors.Is(err, unix.ENOENT) {
		i.diagnostics.localTCPRedirectMiss.Add(1)
		i.logMissingTCPRedirect(ctx, backend, listenerDestination)
		conn.Close()
		return
	}
	if err != nil {
		i.diagnostics.localTCPLookupError.Add(1)
		i.logger.ErrorContext(ctx, "lookup TCP original destination: ", err)
		conn.Close()
		return
	}
	metadata.Inbound = i.Tag()
	metadata.InboundType = i.Type()
	metadata.Destination = M.SocksaddrFromNetIP(original.Destination)
	i.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}

func (i *Inbound) logMissingTCPRedirect(ctx context.Context, backend *ECommon.CgroupBackend, listener netip.AddrPort) {
	if !i.isRedirectListenerDestination(listener, i.listeners.selectedPort()) {
		i.logger.DebugContext(ctx, "unexpected direct connection to eBPF listener: listener=", listener)
		return
	}
	allowed, suppressed := i.tcpWarnings.allow(time.Now())
	if !allowed {
		return
	}
	usage, usageErr := backend.RedirectMapUsage(ECommon.ProtocolTCP)
	failures, failuresErr := backend.RedirectReservationFailures(ECommon.ProtocolTCP)
	args := []any{
		"missing TCP redirect state for valid token",
		": listener=", listener,
		" lookup_and_delete=", backend.LookupAndDeleteMode(),
		" redirect_reservation_failures=", failures,
	}
	if errors.Is(usageErr, unix.ENODATA) {
		args = append(args, " redirect_state_last_sweep=unknown/", usage.Capacity)
	} else {
		args = append(args, " redirect_state_last_sweep=", usage.Entries, "/", usage.Capacity)
		if usageErr != nil {
			args = append(args, " redirect_state_error=", usageErr)
		}
	}
	if failuresErr != nil {
		args = append(args, " redirect_reservation_failures_error=", failuresErr)
	}
	if suppressed > 0 {
		args = append(args, " (", suppressed, " similar errors suppressed)")
	}
	i.logger.ErrorContext(ctx, args...)
}

func (i *Inbound) isRedirectListenerDestination(destination netip.AddrPort, listenerPort uint16) bool {
	if !destination.IsValid() || destination.Port() != listenerPort {
		return false
	}
	address := destination.Addr().Unmap()
	if address.Is4() {
		return i.redirectIPv4Prefix.IsValid() && i.redirectIPv4Prefix.Contains(address)
	}
	return i.redirectIPv6Prefix.IsValid() && i.redirectIPv6Prefix.Contains(address)
}

func (i *Inbound) NewPacket(buffer *buf.Buffer, oob []byte, source M.Socksaddr) {
	backend := i.cgroupBackendInstance()
	if backend == nil {
		return
	}
	redirectAddress, err := redirectAddressFromOOB(oob)
	if err != nil {
		i.diagnostics.localUDPPacketInfoError.Add(1)
		i.udpWarnings.packetInfo.warn(i.logger, "read UDP redirect address: ", err)
		return
	}
	client := source.AddrPort()
	redirectDestination := netip.AddrPortFrom(redirectAddress, i.listeners.selectedPort())
	cached, bindingReady, loaded := i.udpClientTable.cachedPacketState(client, redirectAddress)
	original := cached.original
	if !loaded {
		original, err = backend.LookupOriginal(ECommon.ProtocolUDP, redirectDestination)
		if errors.Is(err, unix.ENOENT) {
			original, err = backend.RecoverUDPOriginal(redirectDestination)
			if err == nil {
				i.diagnostics.localUDPRedirectRecovery.Add(1)
			}
		}
		if errors.Is(err, unix.ENOENT) {
			original, err = backend.RecoverConnectedUDPOriginal(redirectDestination)
			if err == nil {
				i.diagnostics.localUDPConnectedRecovery.Add(1)
			}
		}
		if err != nil {
			if errors.Is(err, unix.ENOENT) {
				i.diagnostics.localUDPRedirectMiss.Add(1)
			} else {
				i.diagnostics.localUDPLookupError.Add(1)
			}
			i.udpWarnings.originalDestination.warn(i.logger, "lookup UDP original destination: ", err)
			return
		}
	}
	if !bindingReady {
		releasedRedirects := i.udpClientTable.setBinding(
			client,
			original.Destination,
			redirectAddress,
			original.ConnectedUDP,
		)
		i.deleteUDPRedirects(releasedRedirects)
	}
	i.udpNat.NewPacket([][]byte{buffer.Bytes()}, source, M.SocksaddrFromNetIP(original.Destination), original.ConnectedUDP)
}

func (i *Inbound) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	metadata := adapter.InboundContext{
		Inbound:     i.Tag(),
		InboundType: i.Type(),
		Source:      source,
		Destination: destination,
	}
	if clientState, loaded := i.udpClientTable.load(source.AddrPort()); loaded {
		metadata.UDPConnect = clientState.isConnected()
	}
	i.router.RoutePacketConnectionEx(ctx, conn, metadata, onClose)
}

func (i *Inbound) preparePacketConnection(source M.Socksaddr, destination M.Socksaddr, userData any) (bool, context.Context, N.PacketWriter, N.CloseHandlerFunc) {
	connectedUDP, _ := userData.(bool)
	ctx := log.ContextWithNewID(i.ctx)
	client := source.AddrPort()
	clientState := i.udpClientTable.loadOrCreate(client)
	clientState.setConnected(connectedUDP, destination.AddrPort())
	writer := &udpPacketWriter{
		inbound:     i,
		client:      client,
		clientState: clientState,
	}
	return true, ctx, writer, func(error) {
		i.deleteUDPRedirects(i.udpClientTable.delete(writer.client, writer.clientState))
	}
}

func (i *Inbound) deleteUDPRedirects(redirectAddresses []netip.Addr) {
	if len(redirectAddresses) == 0 {
		return
	}
	backend := i.cgroupBackendInstance()
	if backend == nil {
		return
	}
	for _, redirectAddress := range redirectAddresses {
		redirectDestination := netip.AddrPortFrom(redirectAddress, i.listeners.selectedPort())
		if err := backend.DeleteRedirect(ECommon.ProtocolUDP, redirectDestination); err != nil {
			i.diagnostics.localUDPCleanupError.Add(1)
			i.udpWarnings.cleanup.warn(i.logger, "delete UDP redirect mapping for ", redirectDestination, ": ", err)
		}
	}
}

func (i *Inbound) socketControl(ipv6Listener bool) control.Func {
	return func(network string, address string, rawConn syscall.RawConn) error {
		if ipv6Listener {
			return control.Raw(rawConn, func(fd uintptr) error {
				if err := unix.SetsockoptInt(int(fd), unix.SOL_IPV6, unix.IPV6_TRANSPARENT, 1); err != nil {
					return err
				}
				if err := unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_V6ONLY, 1); err != nil {
					return err
				}
				if strings.HasPrefix(network, "udp") {
					return unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_RECVPKTINFO, 1)
				}
				return nil
			})
		}
		if network == "udp4" {
			return control.Raw(rawConn, func(fd uintptr) error {
				return unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_PKTINFO, 1)
			})
		}
		return nil
	}
}

type udpPacketWriter struct {
	debug       eBPFDebugUDPWriterState
	inbound     *Inbound
	client      netip.AddrPort
	clientState *udpClientState
}

func (w *udpPacketWriter) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	defer buffer.Release()
	destinationAddress := destination.AddrPort()
	binding, loaded := w.clientState.redirectBinding(destinationAddress)
	if !loaded {
		w.inbound.diagnostics.localUDPBindingMiss.Add(1)
		w.inbound.debug.observeUDPBindingMiss(
			&w.debug,
			false,
			w.inbound.logger,
			&w.inbound.udpClientTable,
			w.client,
			destinationAddress,
			w.clientState,
		)
		return E.New("missing UDP redirect binding for ", destination)
	}
	return w.inbound.listeners.writeUDP(buffer.Bytes(), binding.packetInfo, w.client, binding.address)
}

func redirectAddressFromOOB(oob []byte) (netip.Addr, error) {
	for len(oob) > 0 {
		header, data, remainder, err := unix.ParseOneSocketControlMessage(oob)
		if err != nil {
			return netip.Addr{}, E.Cause(err, "parse IP packet info")
		}
		switch {
		case header.Level == unix.IPPROTO_IP && header.Type == unix.IP_PKTINFO:
			if len(data) < unix.SizeofInet4Pktinfo {
				return netip.Addr{}, E.New("invalid IPv4 packet info length: ", len(data))
			}
			var address [4]byte
			copy(address[:], data[8:12])
			return netip.AddrFrom4(address), nil
		case header.Level == unix.IPPROTO_IPV6 && header.Type == unix.IPV6_PKTINFO:
			if len(data) < unix.SizeofInet6Pktinfo {
				return netip.Addr{}, E.New("invalid IPv6 packet info length: ", len(data))
			}
			var address [16]byte
			copy(address[:], data[:16])
			return netip.AddrFrom16(address), nil
		}
		oob = remainder
	}
	return netip.Addr{}, E.New("IP packet info is missing")
}
