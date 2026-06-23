package wireguard

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"
	"github.com/sagernet/wireguard-go/conn"
)

var _ conn.Bind = (*ClientBind)(nil)

const (
	clientBindPausePollInterval = 100 * time.Millisecond
	clientBindRetryInterval     = time.Second
)

type ClientBind struct {
	ctx                 context.Context
	logger              logger.Logger
	pauseManager        pause.Manager
	bindCtx             context.Context
	bindDone            context.CancelFunc
	dialer              N.Dialer
	reservedForEndpoint map[netip.AddrPort][3]uint8
	connAccess          sync.Mutex
	conn                *wireConn
	done                chan struct{}
	isConnect           bool
	connectAddr         netip.AddrPort
	reserved            [3]uint8
}

func NewClientBind(ctx context.Context, logger logger.Logger, dialer N.Dialer, isConnect bool, connectAddr netip.AddrPort, reserved [3]uint8) *ClientBind {
	return &ClientBind{
		ctx:                 ctx,
		logger:              logger,
		pauseManager:        service.FromContext[pause.Manager](ctx),
		dialer:              dialer,
		reservedForEndpoint: make(map[netip.AddrPort][3]uint8),
		done:                make(chan struct{}),
		isConnect:           isConnect,
		connectAddr:         connectAddr,
		reserved:            reserved,
	}
}

func (c *ClientBind) connect() (*wireConn, error) {
	c.connAccess.Lock()
	bindCtx := c.bindCtx
	done := c.done
	if isDone(done) {
		c.connAccess.Unlock()
		return nil, net.ErrClosed
	}
	serverConn := c.conn
	if serverConn != nil && !isDone(serverConn.done) {
		c.connAccess.Unlock()
		return serverConn, nil
	}
	c.connAccess.Unlock()

	var (
		udpConn net.PacketConn
		err     error
	)
	if c.isConnect {
		var conn net.Conn
		conn, err = c.dialer.DialContext(bindCtx, N.NetworkUDP, M.SocksaddrFromNetIP(c.connectAddr))
		if err == nil {
			udpConn = bufio.NewUnbindPacketConn(conn)
		}
	} else {
		udpConn, err = c.dialer.ListenPacket(bindCtx, M.Socksaddr{Addr: netip.IPv4Unspecified()})
	}
	if err != nil {
		return nil, err
	}
	serverConn = &wireConn{
		PacketConn: udpConn,
		done:       make(chan struct{}),
	}

	c.connAccess.Lock()
	if done != c.done || isDone(done) {
		c.connAccess.Unlock()
		_ = serverConn.Close()
		return nil, net.ErrClosed
	}
	if c.conn != nil && !isDone(c.conn.done) {
		currentConn := c.conn
		c.connAccess.Unlock()
		_ = serverConn.Close()
		return currentConn, nil
	}
	c.conn = serverConn
	c.connAccess.Unlock()
	return serverConn, nil
}

func (c *ClientBind) Open(port uint16) (fns []conn.ReceiveFunc, actualPort uint16, err error) {
	c.connAccess.Lock()
	defer c.connAccess.Unlock()
	select {
	case <-c.done:
		c.done = make(chan struct{})
	default:
	}
	c.bindCtx, c.bindDone = context.WithCancel(c.ctx)
	return []conn.ReceiveFunc{c.receive}, 0, nil
}

func (c *ClientBind) receive(packets [][]byte, sizes []int, eps []conn.Endpoint) (count int, err error) {
	udpConn, err := c.connect()
	if err != nil {
		if isDone(c.done) {
			return
		}
		c.logger.Error(E.Cause(err, "connect to server"))
		err = nil
		if !c.waitAfterFailure() {
			return
		}
		return
	}
	n, addr, err := udpConn.ReadFrom(packets[0])
	if err != nil {
		udpConn.Close()
		if !isDone(c.done) {
			c.logger.Error(E.Cause(err, "read packet"))
		}
		err = nil
		return
	}
	sizes[0] = n
	if n > 3 {
		b := packets[0]
		clear(b[1:4])
	}
	eps[0] = remoteEndpoint(M.SocksaddrFromNet(addr).Unwrap().AddrPort())
	count = 1
	return
}

func (c *ClientBind) Close() error {
	c.connAccess.Lock()
	select {
	case <-c.done:
	default:
		close(c.done)
	}
	bindDone := c.bindDone
	c.bindDone = nil
	serverConn := c.conn
	c.conn = nil
	c.connAccess.Unlock()
	if bindDone != nil {
		bindDone()
	}
	common.Close(common.PtrOrNil(serverConn))
	return nil
}

func (c *ClientBind) SetMark(mark uint32) error {
	return nil
}

func (c *ClientBind) Send(bufs [][]byte, ep conn.Endpoint, offset int) error {
	udpConn, err := c.connect()
	if err != nil {
		if !c.waitAfterFailure() {
			return err
		}
		return err
	}
	destination := netip.AddrPort(ep.(remoteEndpoint))
	for _, buf := range bufs {
		if offset > 0 {
			buf = buf[offset:]
		}
		if len(buf) > 3 {
			reserved, loaded := c.reservedForEndpoint[destination]
			if !loaded {
				reserved = c.reserved
			}
			copy(buf[1:4], reserved[:])
		}
		_, err = udpConn.WriteToUDPAddrPort(buf, destination)
		if err != nil {
			udpConn.Close()
			return err
		}
	}
	return nil
}

func (c *ClientBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return remoteEndpoint(ap), nil
}

func (c *ClientBind) BatchSize() int {
	return 1
}

func (c *ClientBind) SetReservedForEndpoint(destination netip.AddrPort, reserved [3]byte) {
	c.reservedForEndpoint[destination] = reserved
}

func (c *ClientBind) waitActive() bool {
	for c.pauseManager != nil && c.pauseManager.IsPaused() {
		if !c.waitDelay(clientBindPausePollInterval) {
			return false
		}
	}
	return !isDone(c.done)
}

func (c *ClientBind) waitAfterFailure() bool {
	if c.pauseManager != nil && c.pauseManager.IsPaused() {
		return c.waitActive()
	}
	return c.waitDelay(clientBindRetryInterval)
}

func (c *ClientBind) waitDelay(delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-c.done:
		return false
	case <-c.ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func isDone(done <-chan struct{}) bool {
	select {
	case <-done:
		return true
	default:
		return false
	}
}

type wireConn struct {
	net.PacketConn
	conn   net.Conn
	access sync.Mutex
	done   chan struct{}
}

func (w *wireConn) WriteToUDPAddrPort(b []byte, addr netip.AddrPort) (int, error) {
	if w.conn != nil {
		return w.conn.Write(b)
	}
	return w.PacketConn.WriteTo(b, M.SocksaddrFromNetIP(addr).UDPAddr())
}

func (w *wireConn) Close() error {
	w.access.Lock()
	defer w.access.Unlock()
	select {
	case <-w.done:
		return net.ErrClosed
	default:
	}
	w.PacketConn.Close()
	close(w.done)
	return nil
}

var _ conn.Endpoint = (*remoteEndpoint)(nil)

type remoteEndpoint netip.AddrPort

func (e remoteEndpoint) ClearSrc() {
}

func (e remoteEndpoint) SrcToString() string {
	return ""
}

func (e remoteEndpoint) DstToString() string {
	return (netip.AddrPort)(e).String()
}

func (e remoteEndpoint) DstToBytes() []byte {
	b, _ := (netip.AddrPort)(e).MarshalBinary()
	return b
}

func (e remoteEndpoint) DstIP() netip.Addr {
	return (netip.AddrPort)(e).Addr()
}

func (e remoteEndpoint) SrcIP() netip.Addr {
	return netip.Addr{}
}
