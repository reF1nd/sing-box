//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net"
	"net/netip"
	"strings"
	"sync"
	"syscall"

	commonEBPF "github.com/CHIZI-0618/sing-ebpf"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/udpio"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
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
		ConnectionHandler:   handler,
		OOBPacketHandler:    handler,
		DisablePacketOutput: true,
		DisableLog:          true,
		SocketControl:       i.socketControl(ipv6Listener),
	})
}

func (i *Inbound) newListener(network string, ipv6Listener bool, port uint16) *listener.Listener {
	return i.newInternalListener(i, network, ipv6Listener, port)
}

func (i *Inbound) startTCListeners() error {
	return i.listeners.start(
		i.enableTCP,
		i.enableUDP,
		true,
		i.localIPv6 || i.sharedIPv6,
		i.newListener,
	)
}

type internalListenerSet struct {
	access    sync.RWMutex
	tcp4      *listener.Listener
	tcp6      *listener.Listener
	udp4      *listener.Listener
	udp6      *listener.Listener
	udp4Batch udpio.OOBPacketBatchWriter
	udp6Batch udpio.OOBPacketBatchWriter
	port      uint16
}

func (s *internalListenerSet) start(
	enableTCP bool,
	enableUDP bool,
	enableIPv4 bool,
	enableIPv6 bool,
	newListener func(network string, ipv6 bool, port uint16) *listener.Listener,
) error {
	s.access.Lock()
	defer s.access.Unlock()
	if !s.isClosedLocked() || s.port != 0 {
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
		if spec.network == N.NetworkUDP {
			batchWriter, created := udpio.NewOOBPacketBatchWriter(current.UDPConn(), spec.ipv6)
			if created {
				if spec.ipv6 {
					s.udp6Batch = batchWriter
				} else {
					s.udp4Batch = batchWriter
				}
			}
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
	s.access.Lock()
	defer s.access.Unlock()
	listeners := []*listener.Listener{s.tcp4, s.tcp6, s.udp4, s.udp6}
	s.tcp4 = nil
	s.tcp6 = nil
	s.udp4 = nil
	s.udp6 = nil
	s.udp4Batch = nil
	s.udp6Batch = nil
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
	s.access.RLock()
	defer s.access.RUnlock()
	return s.isClosedLocked()
}

func (s *internalListenerSet) isClosedLocked() bool {
	return s.tcp4 == nil && s.tcp6 == nil && s.udp4 == nil && s.udp6 == nil
}

func (s *internalListenerSet) selectedPort() uint16 {
	s.access.RLock()
	defer s.access.RUnlock()
	return s.port
}

func (s *internalListenerSet) registerTCTCPListeners(backend *commonEBPF.TCBackend) error {
	s.access.RLock()
	defer s.access.RUnlock()
	for _, registration := range []struct {
		ipv6     bool
		listener net.Listener
	}{
		{false, listenerTCP(s.tcp4)},
		{true, listenerTCP(s.tcp6)},
	} {
		if registration.listener == nil {
			continue
		}
		conn, loaded := registration.listener.(syscall.Conn)
		if !loaded {
			return E.New("TC eBPF TCP listener does not expose syscall.Conn")
		}
		raw, err := conn.SyscallConn()
		if err != nil {
			return err
		}
		var registerErr error
		if err = raw.Control(func(fd uintptr) {
			registerErr = backend.RegisterTCPListener(registration.ipv6, int(fd))
		}); err != nil {
			return err
		}
		if registerErr != nil {
			return registerErr
		}
	}
	return nil
}

func listenerTCP(current *listener.Listener) net.Listener {
	if current == nil {
		return nil
	}
	return current.TCPListener()
}

func (s *internalListenerSet) writeUDP(payload, packetInfo []byte, client netip.AddrPort, source netip.Addr) error {
	s.access.RLock()
	defer s.access.RUnlock()
	current := s.udp4
	if source.Is6() {
		current = s.udp6
	}
	if current == nil {
		return E.New("eBPF UDP redirect listener is unavailable for ", source)
	}
	_, _, err := current.UDPConn().WriteMsgUDPAddrPort(payload, packetInfo, client)
	return err
}

func (s *internalListenerSet) writeUDPBatch(
	buffers []*buf.Buffer,
	packetInfos [][]byte,
	client netip.AddrPort,
	sources []netip.Addr,
) error {
	if len(buffers) == 0 || len(buffers) != len(packetInfos) || len(buffers) != len(sources) {
		buf.ReleaseMulti(buffers)
		return E.New("invalid eBPF UDP OOB batch")
	}
	s.access.RLock()
	defer s.access.RUnlock()
	type packetGroup struct {
		buffers      []*buf.Buffer
		packetInfos  [][]byte
		destinations []M.Socksaddr
	}
	var ipv4Group, ipv6Group packetGroup
	for index, source := range sources {
		group := &ipv4Group
		if source.Is6() {
			group = &ipv6Group
		}
		group.buffers = append(group.buffers, buffers[index])
		group.packetInfos = append(group.packetInfos, packetInfos[index])
		group.destinations = append(group.destinations, M.SocksaddrFromNetIP(client))
	}
	writeGroup := func(group packetGroup, current *listener.Listener, batchWriter udpio.OOBPacketBatchWriter) error {
		if len(group.buffers) == 0 {
			return nil
		}
		if current == nil {
			buf.ReleaseMulti(group.buffers)
			return E.New("eBPF UDP redirect listener is unavailable for batch address family")
		}
		if batchWriter != nil {
			return batchWriter.WriteOOBPacketBatch(group.buffers, group.packetInfos, group.destinations)
		}
		defer buf.ReleaseMulti(group.buffers)
		for index, buffer := range group.buffers {
			if _, _, err := current.UDPConn().WriteMsgUDPAddrPort(buffer.Bytes(), group.packetInfos[index], group.destinations[index].AddrPort()); err != nil {
				return err
			}
		}
		return nil
	}
	if err := writeGroup(ipv4Group, s.udp4, s.udp4Batch); err != nil {
		buf.ReleaseMulti(ipv6Group.buffers)
		return err
	}
	return writeGroup(ipv6Group, s.udp6, s.udp6Batch)
}

func (s *internalListenerSet) String() string {
	s.access.RLock()
	defer s.access.RUnlock()
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
