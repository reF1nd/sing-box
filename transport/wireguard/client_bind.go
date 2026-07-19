package wireguard

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
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
	bindCtx             context.Context
	bindDone            context.CancelFunc
	dialer              N.Dialer
	pauseManager        pause.Manager
	reservedAccess      sync.RWMutex
	reservedForEndpoint map[netip.AddrPort][3]uint8
	connAccess          sync.Mutex
	conn                atomic.Pointer[wireConn]
	done                chan struct{}
	closed              atomic.Bool
	destination         M.Socksaddr
	reserved            [3]uint8
}

func NewClientBind(ctx context.Context, logger logger.Logger, dialer N.Dialer, destination M.Socksaddr, reserved [3]uint8) *ClientBind {
	return &ClientBind{
		ctx:                 ctx,
		logger:              logger,
		dialer:              dialer,
		pauseManager:        service.FromContext[pause.Manager](ctx),
		reservedForEndpoint: make(map[netip.AddrPort][3]uint8),
		done:                make(chan struct{}),
		destination:         destination,
		reserved:            reserved,
	}
}

func (c *ClientBind) currentDone() <-chan struct{} {
	c.connAccess.Lock()
	done := c.done
	c.connAccess.Unlock()
	return done
}

func (c *ClientBind) connect() (*wireConn, error) {
	serverConn := c.conn.Load()
	if serverConn != nil && !isDone(serverConn.done) {
		return serverConn, nil
	}
	c.connAccess.Lock()
	bindCtx := c.bindCtx
	if bindCtx == nil {
		bindCtx = c.ctx
	}
	done := c.done
	if isDone(done) {
		c.connAccess.Unlock()
		return nil, net.ErrClosed
	}
	serverConn = c.conn.Load()
	if serverConn != nil && !isDone(serverConn.done) {
		c.connAccess.Unlock()
		return serverConn, nil
	}
	c.connAccess.Unlock()

	udpConn, err := c.dialer.ListenPacket(bindCtx, c.destination)
	if err != nil {
		return nil, err
	}
	serverConn = &wireConn{
		PacketConn: bufio.NewPacketConn(udpConn),
		done:       make(chan struct{}),
	}

	c.connAccess.Lock()
	if done != c.done || isDone(done) {
		c.connAccess.Unlock()
		_ = serverConn.Close()
		return nil, net.ErrClosed
	}
	if currentConn := c.conn.Load(); currentConn != nil && !isDone(currentConn.done) {
		c.connAccess.Unlock()
		_ = serverConn.Close()
		return currentConn, nil
	}
	c.conn.Store(serverConn)
	c.connAccess.Unlock()
	return serverConn, nil
}

func (c *ClientBind) Open(port uint16) (fns []conn.ReceiveFunc, actualPort uint16, err error) {
	c.connAccess.Lock()
	defer c.connAccess.Unlock()
	if c.closed.Load() {
		return nil, 0, net.ErrClosed
	}
	select {
	case <-c.done:
		c.done = make(chan struct{})
	default:
	}
	done := c.done
	if c.bindDone != nil {
		c.bindDone()
	}
	c.bindCtx, c.bindDone = context.WithCancel(c.ctx)
	return []conn.ReceiveFunc{func(slab []byte, packets []conn.ReceivedPacket) (int, error) {
		return c.receive(done, slab, packets)
	}}, 0, nil
}

func (c *ClientBind) Shutdown() error {
	c.closed.Store(true)
	return c.Close()
}

func (c *ClientBind) receive(done <-chan struct{}, slab []byte, packets []conn.ReceivedPacket) (int, error) {
	if isDone(done) {
		return 0, net.ErrClosed
	}
	udpConn, err := c.connect()
	if err != nil {
		if isDone(done) {
			return 0, net.ErrClosed
		}
		c.logger.Error(E.Cause(err, "connect to server"))
		if !c.waitAfterFailure(done) {
			return 0, net.ErrClosed
		}
		return 0, nil
	}
	n, addr, err := udpConn.ReadFrom(slab)
	if err != nil {
		if isDone(done) {
			return 0, net.ErrClosed
		}
		if udpConn.Close() != nil {
			return 0, nil
		}
		c.logger.Error(E.Cause(err, "read packet"))
		if !c.waitAfterFailure(done) {
			return 0, net.ErrClosed
		}
		return 0, nil
	}
	source := M.SocksaddrFromNet(addr).Unwrap().AddrPort()
	if n > 3 {
		c.reservedAccess.RLock()
		reserved, loaded := c.reservedForEndpoint[source]
		c.reservedAccess.RUnlock()
		if !loaded {
			reserved = c.reserved
		}
		if reserved != [3]uint8{} {
			clear(slab[1:4])
		}
	}
	packets[0] = conn.ReceivedPacket{Size: n, Endpoint: remoteEndpoint(source)}
	return 1, nil
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
	serverConn := c.conn.Swap(nil)
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
		return err
	}
	destination := netip.AddrPort(ep.(remoteEndpoint))
	for _, buf := range bufs {
		if offset > 0 {
			buf = buf[offset:]
		}
		if len(buf) > 3 {
			c.reservedAccess.RLock()
			reserved, loaded := c.reservedForEndpoint[netip.AddrPortFrom(destination.Addr().Unmap(), destination.Port())]
			c.reservedAccess.RUnlock()
			if !loaded {
				reserved = c.reserved
			}
			if reserved != [3]uint8{} {
				copy(buf[1:4], reserved[:])
			}
		}
		_, err = udpConn.WriteTo(buf, M.SocksaddrFromNetIP(destination).UDPAddr())
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
	c.reservedAccess.Lock()
	c.reservedForEndpoint[netip.AddrPortFrom(destination.Addr().Unmap(), destination.Port())] = reserved
	c.reservedAccess.Unlock()
}

func (c *ClientBind) waitActive(done <-chan struct{}) bool {
	for c.pauseManager != nil && c.pauseManager.IsNetworkPaused() {
		if !c.waitDelay(done, clientBindPausePollInterval) {
			return false
		}
	}
	return !isDone(done)
}

func (c *ClientBind) waitAfterFailure(done <-chan struct{}) bool {
	if c.pauseManager != nil && c.pauseManager.IsNetworkPaused() {
		return c.waitActive(done)
	}
	return c.waitDelay(done, clientBindRetryInterval)
}

func (c *ClientBind) waitDelay(done <-chan struct{}, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-done:
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
	access sync.Mutex
	done   chan struct{}
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
	return netip.AddrPort(e).String()
}

func (e remoteEndpoint) DstToBytes() []byte {
	b, _ := netip.AddrPort(e).MarshalBinary()
	return b
}

func (e remoteEndpoint) DstIP() netip.Addr {
	return netip.AddrPort(e).Addr()
}

func (e remoteEndpoint) SrcIP() netip.Addr {
	return netip.Addr{}
}
