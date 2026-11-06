package dialer

import (
	"context"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/database64128/tfo-go/v2"
)

type slowOpenConn struct {
	dialer       *tfo.Dialer
	dialFunc     func(ctx context.Context, dialer *tfo.Dialer, network string, address string, payload []byte) (net.Conn, error)
	ctx          context.Context
	cancel       context.CancelFunc
	netns        string
	network      string
	destination  M.Socksaddr
	conn         atomic.Pointer[net.TCPConn]
	create       chan struct{}
	done         chan struct{}
	access       sync.Mutex
	closeAccess  sync.Mutex
	closed       bool
	closeOnce    sync.Once
	tcpClosed    atomic.Bool
	closeHandler atomic.Value // func(*net.TCPConn)
	err          error
}

func (c *slowOpenConn) setCloseHandler(handler func(*net.TCPConn)) {
	c.closeHandler.Store(handler)
}

func (c *slowOpenConn) closeTCP(conn *net.TCPConn) {
	if !c.tcpClosed.Swap(true) {
		if handler, loaded := c.closeHandler.Load().(func(*net.TCPConn)); loaded {
			handler(conn)
		}
		_ = conn.Close()
	}
}

func DialSlowContext(dialer *tfo.Dialer, ctx context.Context, netns string, network string, destination M.Socksaddr) (net.Conn, error) {
	if dialer.DisableTFO || N.NetworkName(network) != N.NetworkTCP {
		switch N.NetworkName(network) {
		case N.NetworkTCP, N.NetworkUDP:
			return dialer.Dialer.DialContext(ctx, network, destination.String())
		default:
			return dialer.Dialer.DialContext(ctx, network, destination.AddrString())
		}
	}
	dialCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	return &slowOpenConn{
		dialer:      dialer,
		ctx:         dialCtx,
		cancel:      cancel,
		netns:       netns,
		network:     network,
		destination: destination,
		create:      make(chan struct{}),
		done:        make(chan struct{}),
	}, nil
}

func (c *slowOpenConn) Read(b []byte) (n int, err error) {
	conn := c.conn.Load()
	if conn != nil {
		return conn.Read(b)
	}
	select {
	case <-c.create:
		if c.err != nil {
			return 0, c.err
		}
		return c.conn.Load().Read(b)
	case <-c.done:
		return 0, os.ErrClosed
	}
}

func (c *slowOpenConn) Write(b []byte) (n int, err error) {
	tcpConn := c.conn.Load()
	if tcpConn != nil {
		return tcpConn.Write(b)
	}
	c.access.Lock()
	defer c.access.Unlock()
	select {
	case <-c.create:
		if c.err != nil {
			return 0, c.err
		}
		return c.conn.Load().Write(b)
	case <-c.done:
		return 0, os.ErrClosed
	default:
	}
	conn, err := listener.ListenNetworkNamespace[net.Conn](c.ctx, c.netns, func() (net.Conn, error) {
		if c.dialFunc != nil {
			return c.dialFunc(c.ctx, c.dialer, c.network, c.destination.String(), b)
		}
		return c.dialer.DialContext(c.ctx, c.network, c.destination.String(), b)
	})
	if err != nil {
		c.err = err
	} else {
		n = len(b)
		tcpConn := conn.(*net.TCPConn)
		c.closeAccess.Lock()
		closed := c.closed
		if !closed {
			c.conn.Store(tcpConn)
		}
		c.closeAccess.Unlock()
		if closed {
			c.closeTCP(tcpConn)
			err = os.ErrClosed
			c.err = err
		}
	}
	close(c.create)
	return
}

func (c *slowOpenConn) Close() error {
	c.closeOnce.Do(func() {
		c.closeAccess.Lock()
		c.closed = true
		conn := c.conn.Load()
		c.closeAccess.Unlock()
		close(c.done)
		c.cancel()
		if conn != nil {
			c.closeTCP(conn)
		}
	})
	return nil
}

func (c *slowOpenConn) LocalAddr() net.Addr {
	conn := c.conn.Load()
	if conn == nil {
		return M.Socksaddr{}
	}
	return conn.LocalAddr()
}

func (c *slowOpenConn) RemoteAddr() net.Addr {
	conn := c.conn.Load()
	if conn == nil {
		return M.Socksaddr{}
	}
	return conn.RemoteAddr()
}

func (c *slowOpenConn) SetDeadline(t time.Time) error {
	conn := c.conn.Load()
	if conn == nil {
		return os.ErrInvalid
	}
	return conn.SetDeadline(t)
}

func (c *slowOpenConn) SetReadDeadline(t time.Time) error {
	conn := c.conn.Load()
	if conn == nil {
		return os.ErrInvalid
	}
	return conn.SetReadDeadline(t)
}

func (c *slowOpenConn) SetWriteDeadline(t time.Time) error {
	conn := c.conn.Load()
	if conn == nil {
		return os.ErrInvalid
	}
	return conn.SetWriteDeadline(t)
}

func (c *slowOpenConn) Upstream() any {
	return common.PtrOrNil(c.conn.Load())
}

func (c *slowOpenConn) ReaderReplaceable() bool {
	return c.conn.Load() != nil
}

func (c *slowOpenConn) WriterReplaceable() bool {
	return c.conn.Load() != nil
}

func (c *slowOpenConn) NeedHandshake() bool {
	return c.conn.Load() == nil
}

func (c *slowOpenConn) WriteTo(w io.Writer) (n int64, err error) {
	conn := c.conn.Load()
	if conn == nil {
		select {
		case <-c.create:
			if c.err != nil {
				return 0, c.err
			}
			conn = c.conn.Load()
		case <-c.done:
			return 0, os.ErrClosed
		}
	}
	return bufio.Copy(w, conn)
}
