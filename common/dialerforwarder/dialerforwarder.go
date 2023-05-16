package dialerforwarder

import (
	"context"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"sync/atomic"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/canceler"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/udpnat"
	"github.com/sagernet/tfo-go"
)

type DialerForwarder struct {
	ctx         context.Context
	logger      log.ContextLogger
	dialer      N.Dialer
	port        uint16
	network     []string
	tcpFastOpen bool
	udpFragment *bool
	udpTimeout  time.Duration

	destination          M.Socksaddr
	tcpListener          net.Listener
	udpConn              *net.UDPConn
	udpNat               *udpnat.Service[netip.AddrPort]
	packetOutboundClosed chan struct{}
	packetOutbound       chan *udpPacket
	inShutdown           atomic.Bool
}

func NewDialerForwarder(ctx context.Context, logger log.ContextLogger, dialer N.Dialer, port uint16, destination M.Socksaddr, network []string, tcpFastOpen bool, udpFragment *bool, udpTimeout time.Duration) *DialerForwarder {
	return &DialerForwarder{
		ctx:         ctx,
		logger:      logger,
		dialer:      dialer,
		port:        port,
		network:     network,
		destination: destination,
		tcpFastOpen: tcpFastOpen,
		udpFragment: udpFragment,
		udpTimeout:  udpTimeout,
	}
}

func (s *DialerForwarder) Start() error {
	s.packetOutboundClosed = make(chan struct{})
	s.packetOutbound = make(chan *udpPacket)
	udpNatTimeout := int64(s.udpTimeout.Seconds())
	if udpNatTimeout <= 0 {
		udpNatTimeout = int64(C.UDPTimeout.Seconds())
	}
	s.udpNat = udpnat.New[netip.AddrPort](udpNatTimeout, s)
	if common.Contains(s.network, N.NetworkTCP) {
		var err error
		if !s.tcpFastOpen {
			s.tcpListener, err = net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: int(s.port)})
		} else {
			s.tcpListener, err = tfo.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: int(s.port)})
		}
		if err != nil {
			return err
		}
		s.logger.Info("tcp server started at ", s.tcpListener.Addr())
		go s.dialTCP()
	}
	if common.Contains(s.network, N.NetworkUDP) {
		var err error
		var lc net.ListenConfig
		var udpFragment bool
		if s.udpFragment != nil {
			udpFragment = *s.udpFragment
		} else {
			udpFragment = false
		}
		if !udpFragment {
			lc.Control = control.Append(lc.Control, control.DisableUDPFragment())
		}
		udpConn, err := lc.ListenPacket(s.ctx, N.NetworkUDP, net.JoinHostPort("127.0.0.1", strconv.Itoa(int(s.port))))
		if err != nil {
			return err
		}
		s.udpConn = udpConn.(*net.UDPConn)
		s.logger.Info("udp server started at ", s.udpConn.LocalAddr())
		go s.dialUDP()
		go s.handleUDPOut()
	}
	return nil
}

func (s *DialerForwarder) Close() error {
	s.inShutdown.Store(true)
	if s.tcpListener != nil {
		err := s.tcpListener.Close()
		if err != nil {
			return err
		}
	}
	return common.Close(common.PtrOrNil(s.udpConn))
}

func (s *DialerForwarder) dialTCP() {
	for {
		conn, err := s.tcpListener.Accept()
		if err != nil {
			if netError, isNetError := err.(net.Error); isNetError && netError.Temporary() {
				s.logger.Error(err)
				continue
			}
			if s.inShutdown.Load() && E.IsClosed(err) {
				return
			}
			s.tcpListener.Close()
			s.logger.Error("serve error: ", err)
			continue
		}
		go s.handleTCP(conn)
	}
}

func (s *DialerForwarder) handleTCP(conn net.Conn) {
	defer conn.Close()
	outConn, err := s.dialer.DialContext(s.ctx, N.NetworkTCP, s.destination)
	if err != nil {
		s.logger.Error(E.Cause(err, "outbound connection failed"))
		return
	}
	defer outConn.Close()
	err = copyEarlyConn(s.ctx, conn, outConn)
	if err != nil {
		s.logger.Error(err)
		return
	}
}

func (s *DialerForwarder) dialUDP() {
	defer close(s.packetOutboundClosed)
	for {
		buffer := buf.NewPacket()
		n, addr, err := s.udpConn.ReadFromUDPAddrPort(buffer.FreeBytes())
		if err != nil {
			buffer.Release()
			return
		}
		buffer.Truncate(n)
		err = s.handleUDP(buffer, addr)
		if err != nil {
			buffer.Release()
			s.logger.Error(E.Cause(err, "process packet from ", M.SocksaddrFromNetIP(addr).Unwrap()))
		}
	}
}

func (s *DialerForwarder) handleUDP(buffer *buf.Buffer, addr netip.AddrPort) error {
	metadata := M.Metadata{
		Source:      M.SocksaddrFromNetIP(addr).Unwrap(),
		Destination: s.destination,
	}
	s.udpNat.NewContextPacket(s.ctx, metadata.Source.AddrPort(), buffer, metadata, func(natConn N.PacketConn) (context.Context, N.PacketWriter) {
		return log.ContextWithNewID(s.ctx), &udpnat.DirectBackWriter{Source: (*udpPacketService)(s), Nat: natConn}
	})
	return nil
}

func (s *DialerForwarder) handleUDPOut() {
	for {
		select {
		case packet := <-s.packetOutbound:
			err := s.writePacket(packet.buffer, packet.destination)
			if err != nil && !E.IsClosed(err) {
				s.logger.Error(E.New("write back udp: ", err))
			}
			continue
		case <-s.packetOutboundClosed:
		}
		for {
			select {
			case packet := <-s.packetOutbound:
				packet.buffer.Release()
			default:
				return
			}
		}
	}
}

func (s *DialerForwarder) writePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	defer buffer.Release()
	return common.Error(s.udpConn.WriteToUDPAddrPort(buffer.Bytes(), destination.AddrPort()))
}

type udpPacket struct {
	buffer      *buf.Buffer
	destination M.Socksaddr
}

type udpPacketService DialerForwarder

func (s *udpPacketService) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	n, addr, err := s.udpConn.ReadFromUDPAddrPort(buffer.FreeBytes())
	if err != nil {
		return M.Socksaddr{}, err
	}
	buffer.Truncate(n)
	return M.SocksaddrFromNetIP(addr), nil
}

func (s *udpPacketService) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	select {
	case s.packetOutbound <- &udpPacket{buffer, destination}:
		return nil
	case <-s.packetOutboundClosed:
		return os.ErrClosed
	}
}

func (s *udpPacketService) LocalAddr() net.Addr {
	return s.udpConn.LocalAddr()
}

func (s *udpPacketService) SetDeadline(t time.Time) error {
	return s.udpConn.SetDeadline(t)
}

func (s *udpPacketService) SetReadDeadline(t time.Time) error {
	return s.udpConn.SetReadDeadline(t)
}

func (s *udpPacketService) SetWriteDeadline(t time.Time) error {
	return s.udpConn.SetWriteDeadline(t)
}

func (s *udpPacketService) Close() error {
	return s.udpConn.Close()
}

func (s *udpPacketService) WriteIsThreadUnsafe() {
}

func (s *udpPacketService) Upstream() any {
	return s.udpConn
}

func (s *DialerForwarder) NewError(ctx context.Context, err error) {
	common.Close(err)
	if E.IsClosedOrCanceled(err) {
		s.logger.DebugContext(ctx, "connection closed: ", err)
		return
	}
	s.logger.ErrorContext(ctx, err)
}

func (s *DialerForwarder) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata M.Metadata) error {
	outConn, err := s.dialer.ListenPacket(ctx, metadata.Destination)
	if err != nil {
		return N.ReportHandshakeFailure(conn, err)
	}
	udpTimeout := s.udpTimeout
	if udpTimeout <= 0 {
		udpTimeout = C.UDPTimeout
	}
	ctx, packetCancelOutConn := canceler.NewPacketConn(ctx, bufio.NewPacketConn(outConn), udpTimeout)
	return bufio.CopyPacketConn(ctx, conn, packetCancelOutConn)
}

func copyEarlyConn(ctx context.Context, conn net.Conn, serverConn net.Conn) error {
	if cachedReader, isCached := conn.(N.CachedReader); isCached {
		payload := cachedReader.ReadCached()
		if payload != nil && !payload.IsEmpty() {
			_, err := serverConn.Write(payload.Bytes())
			if err != nil {
				return err
			}
			return bufio.CopyConn(ctx, conn, serverConn)
		}
	}
	if earlyConn, isEarlyConn := common.Cast[N.EarlyConn](serverConn); isEarlyConn && earlyConn.NeedHandshake() {
		_payload := buf.New()
		payload := common.Dup(_payload)
		err := conn.SetReadDeadline(time.Now().Add(C.ReadPayloadTimeout))
		if err != os.ErrInvalid {
			if err != nil {
				return err
			}
			_, err = payload.ReadOnceFrom(conn)
			if err != nil && !E.IsTimeout(err) {
				return E.Cause(err, "read payload")
			}
			err = conn.SetReadDeadline(time.Time{})
			if err != nil {
				payload.Release()
				return err
			}
		}
		_, err = serverConn.Write(payload.Bytes())
		if err != nil {
			return N.ReportHandshakeFailure(conn, err)
		}
		runtime.KeepAlive(_payload)
		payload.Release()
	}
	return bufio.CopyConn(ctx, conn, serverConn)
}
