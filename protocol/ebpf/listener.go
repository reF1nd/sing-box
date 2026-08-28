//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net"
	"net/netip"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type internalListenerHandler interface {
	adapter.ConnectionHandler
	adapter.OOBPacketHandler
}

func (i *Inbound) newInternalListener(
	handler internalListenerHandler,
	network string,
	ipv6Listener bool,
	port uint16,
) *listener.Listener {
	listenAddress := netip.IPv4Unspecified()
	if ipv6Listener {
		listenAddress = netip.IPv6Unspecified()
	}
	return listener.New(listener.Options{
		Context: i.ctx,
		Logger:  i.logger,
		Network: []string{network},
		Listen: option.ListenOptions{
			Listen:     common.Ptr(badoption.Addr(listenAddress)),
			ListenPort: port,
		},
		ConnectionHandler:    handler,
		OOBPacketHandler:     handler,
		DisablePacketOutput:  true,
		DisableConnectionLog: true,
		DisableListenerLog:   true,
		SocketControl:        i.socketControl(ipv6Listener),
	})
}

func (i *Inbound) newListener(network string, ipv6Listener bool, port uint16) *listener.Listener {
	return i.newInternalListener(i, network, ipv6Listener, port)
}

type internalListenerSet struct {
	tcp4 *listener.Listener
	tcp6 *listener.Listener
	udp4 *listener.Listener
	udp6 *listener.Listener
	port uint16
}

func (s *internalListenerSet) start(
	enableTCP bool,
	enableUDP bool,
	enableIPv4 bool,
	enableIPv6 bool,
	newListener func(network string, ipv6 bool, port uint16) *listener.Listener,
) error {
	if !s.isClosed() || s.port != 0 {
		return E.New("internal eBPF listeners are already started")
	}
	type listenerSpec struct {
		network string
		ipv6    bool
		target  **listener.Listener
	}
	var specs []listenerSpec
	if enableIPv4 {
		if enableTCP {
			specs = append(specs, listenerSpec{N.NetworkTCP, false, &s.tcp4})
		}
		if enableUDP {
			specs = append(specs, listenerSpec{N.NetworkUDP, false, &s.udp4})
		}
	}
	if enableIPv6 {
		if enableTCP {
			specs = append(specs, listenerSpec{N.NetworkTCP, true, &s.tcp6})
		}
		if enableUDP {
			specs = append(specs, listenerSpec{N.NetworkUDP, true, &s.udp6})
		}
	}
	for _, spec := range specs {
		current := newListener(spec.network, spec.ipv6, s.port)
		*spec.target = current
		if err := current.Start(); err != nil {
			return err
		}
		if s.port == 0 {
			var address net.Addr
			if spec.network == N.NetworkTCP {
				address = current.TCPListener().Addr()
			} else {
				address = current.UDPConn().LocalAddr()
			}
			s.port = M.SocksaddrFromNet(address).Port
			if s.port == 0 {
				return E.New("internal eBPF listener selected an invalid port")
			}
		}
	}
	if s.port == 0 {
		return E.New("internal eBPF listener has no enabled address family or protocol")
	}
	return nil
}

func (s *internalListenerSet) close() error {
	listeners := []*listener.Listener{s.tcp4, s.tcp6, s.udp4, s.udp6}
	s.tcp4 = nil
	s.tcp6 = nil
	s.udp4 = nil
	s.udp6 = nil
	s.port = 0
	var closeErr error
	for _, current := range listeners {
		if current != nil {
			closeErr = E.Errors(closeErr, common.Close(current))
		}
	}
	return closeErr
}

func (s *internalListenerSet) isClosed() bool {
	return s.tcp4 == nil && s.tcp6 == nil && s.udp4 == nil && s.udp6 == nil
}

func (s *internalListenerSet) selectedPort() uint16 {
	return s.port
}

func (s *internalListenerSet) String() string {
	var listeners []string
	if s.tcp4 != nil {
		listeners = append(listeners, "tcp4="+s.tcp4.TCPListener().Addr().String())
	}
	if s.tcp6 != nil {
		listeners = append(listeners, "tcp6="+s.tcp6.TCPListener().Addr().String())
	}
	if s.udp4 != nil {
		listeners = append(listeners, "udp4="+s.udp4.UDPConn().LocalAddr().String())
	}
	if s.udp6 != nil {
		listeners = append(listeners, "udp6="+s.udp6.UDPConn().LocalAddr().String())
	}
	return strings.Join(listeners, ", ")
}

func (s *internalListenerSet) udp(ipv6 bool) *listener.Listener {
	if ipv6 {
		return s.udp6
	}
	return s.udp4
}

func (s *internalListenerSet) writeUDP(
	payload []byte,
	packetInfo []byte,
	client netip.AddrPort,
	redirectAddress netip.Addr,
) error {
	udpListener := s.udp(redirectAddress.Is6())
	if udpListener == nil {
		addressFamily := "IPv4"
		if redirectAddress.Is6() {
			addressFamily = "IPv6"
		}
		return E.New(addressFamily, " eBPF UDP redirect listener is unavailable")
	}
	_, _, err := udpListener.UDPConn().WriteMsgUDPAddrPort(payload, packetInfo, client)
	return err
}
