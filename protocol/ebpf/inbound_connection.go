//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"strings"
	"syscall"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"golang.org/x/sys/unix"
)

func (i *Inbound) closeListeners() error {
	return i.listeners.close()
}

func (i *Inbound) NewConnection(
	ctx context.Context,
	conn net.Conn,
	metadata adapter.InboundContext,
	onClose N.CloseHandlerFunc,
) {
	backend := i.tcBackend()
	if backend == nil {
		_ = conn.Close()
		return
	}
	i.newTCConnection(ctx, backend, conn, metadata, onClose)
}

func (i *Inbound) NewPacket(buffer *buf.Buffer, oob []byte, source M.Socksaddr) {
	backend := i.tcBackend()
	if backend == nil {
		return
	}
	i.newTCPacket(backend, buffer, oob, source)
}

func (i *Inbound) NewPacketConnectionEx(
	ctx context.Context,
	conn N.PacketConn,
	source M.Socksaddr,
	destination M.Socksaddr,
	onClose N.CloseHandlerFunc,
) {
	metadata := adapter.InboundContext{
		Inbound:     i.Tag(),
		InboundType: i.Type(),
		Source:      source,
		Destination: destination,
	}
	if clientState, loaded := i.udpClientTable.load(source.AddrPort()); loaded {
		metadata.SourceMACAddress = clientState.sourceMACAddress()
		metadata.ProcessInfo = i.lookupProcessInfo(clientState.processSocketCookie())
	}
	i.router.RoutePacketConnectionEx(ctx, conn, metadata, onClose)
}

func (i *Inbound) preparePacketConnection(
	source M.Socksaddr,
	destination M.Socksaddr,
	_ any,
) (bool, context.Context, N.PacketWriter, N.CloseHandlerFunc) {
	return i.prepareTCPacketConnection(source, destination)
}

func (i *Inbound) socketControl(ipv6Listener bool) control.Func {
	return func(network string, _ string, rawConn syscall.RawConn) error {
		if ipv6Listener {
			return control.Raw(rawConn, func(fd uintptr) error {
				if err := unix.SetsockoptInt(int(fd), unix.SOL_IPV6, unix.IPV6_TRANSPARENT, 1); err != nil {
					return err
				}
				if err := unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_V6ONLY, 1); err != nil {
					return err
				}
				if strings.HasPrefix(network, "udp") {
					if err := unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_RECVPKTINFO, 1); err != nil {
						return err
					}
					return unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_RECVORIGDSTADDR, 1)
				}
				return nil
			})
		}
		if network == "udp4" {
			return control.Raw(rawConn, func(fd uintptr) error {
				if err := unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_TRANSPARENT, 1); err != nil {
					return err
				}
				if err := unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_PKTINFO, 1); err != nil {
					return err
				}
				return unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_RECVORIGDSTADDR, 1)
			})
		}
		if network == "tcp4" || network == "tcp" {
			return control.Raw(rawConn, func(fd uintptr) error {
				return unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_TRANSPARENT, 1)
			})
		}
		return nil
	}
}

func redirectAddressFromOOB(oob []byte) (netip.Addr, error) {
	address, _, _, err := packetDestinationsFromOOB(oob)
	return address, err
}

func packetDestinationsFromOOB(oob []byte) (netip.Addr, netip.AddrPort, uint32, error) {
	var packetAddress netip.Addr
	var originalDestination netip.AddrPort
	var interfaceIndex uint32
	for len(oob) > 0 {
		header, data, remainder, err := unix.ParseOneSocketControlMessage(oob)
		if err != nil {
			return netip.Addr{}, netip.AddrPort{}, 0, E.Cause(err, "parse IP packet info")
		}
		switch {
		case header.Level == unix.IPPROTO_IP && header.Type == unix.IP_PKTINFO:
			if len(data) < unix.SizeofInet4Pktinfo {
				return netip.Addr{}, netip.AddrPort{}, 0, E.New("invalid IPv4 packet info length: ", len(data))
			}
			interfaceIndex = binary.NativeEndian.Uint32(data[:4])
			var address [4]byte
			copy(address[:], data[8:12])
			packetAddress = netip.AddrFrom4(address)
		case header.Level == unix.IPPROTO_IPV6 && header.Type == unix.IPV6_PKTINFO:
			if len(data) < unix.SizeofInet6Pktinfo {
				return netip.Addr{}, netip.AddrPort{}, 0, E.New("invalid IPv6 packet info length: ", len(data))
			}
			interfaceIndex = binary.NativeEndian.Uint32(data[16:20])
			var address [16]byte
			copy(address[:], data[:16])
			packetAddress = netip.AddrFrom16(address)
		case header.Level == unix.SOL_IP && header.Type == unix.IP_RECVORIGDSTADDR && len(data) >= 8:
			var address [4]byte
			copy(address[:], data[4:8])
			originalDestination = netip.AddrPortFrom(netip.AddrFrom4(address), binary.BigEndian.Uint16(data[2:4]))
		case header.Level == unix.SOL_IPV6 && header.Type == unix.IPV6_RECVORIGDSTADDR && len(data) >= 24:
			var address [16]byte
			copy(address[:], data[8:24])
			originalDestination = netip.AddrPortFrom(netip.AddrFrom16(address), binary.BigEndian.Uint16(data[2:4]))
		}
		oob = remainder
	}
	if !packetAddress.IsValid() {
		return netip.Addr{}, netip.AddrPort{}, 0, E.New("IP packet info is missing")
	}
	return packetAddress, originalDestination, interfaceIndex, nil
}
