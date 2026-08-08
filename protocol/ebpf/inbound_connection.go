//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"syscall"

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
	i.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}

func (i *Inbound) NewPacket(buffer *buf.Buffer, oob []byte, source M.Socksaddr) {
	backend := i.cgroupBackendInstance()
	if backend == nil {
		return
	}
	redirectAddress, err := redirectAddressFromOOB(oob)
	if err != nil {
		i.udpWarnings.packetInfo.warn(i.logger, "read UDP redirect address: ", err)
		return
	}
	client := source.AddrPort()
	redirectDestination := netip.AddrPortFrom(redirectAddress, i.listeners.selectedPort())
	cached, bindingReady, loaded := i.udpClientTable.cachedPacketState(client, redirectAddress)
	original := cached.original
	if !loaded {
		original, err = backend.LookupOriginal(ECommon.ProtocolUDP, redirectDestination)
		if err != nil {
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
	clientState.setConnected(connectedUDP)
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
	inbound     *Inbound
	client      netip.AddrPort
	clientState *udpClientState
}

func (w *udpPacketWriter) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	defer buffer.Release()
	binding, loaded := w.clientState.redirectBinding(destination.AddrPort())
	if !loaded {
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
