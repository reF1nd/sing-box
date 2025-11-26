package transport

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio/deadline"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	mDNS "github.com/miekg/dns"
)

var _ adapter.DNSTransport = (*TCPTransport)(nil)

type dnsTransportManager interface {
	markPipelineDetected() bool
	isPipelineDetected() bool
	getDetectionCounters() (*int32, *int32, *int32)
	removeActiveConn(conn *reuseableDNSConn)
}

func RegisterTCP(registry *dns.TransportRegistry) {
	dns.RegisterTransport[option.RemoteTCPDNSServerOptions](registry, C.DNSTypeTCP, NewTCP)
}

type TCPTransport struct {
	dns.TransportAdapter
	dialer     N.Dialer
	serverAddr M.Socksaddr
	pipelinePool
}

func NewTCP(ctx context.Context, logger log.ContextLogger, tag string, options option.RemoteTCPDNSServerOptions) (adapter.DNSTransport, error) {
	transportDialer, err := dns.NewRemoteDialer(ctx, options.RemoteDNSServerOptions)
	if err != nil {
		return nil, err
	}
	serverAddr := options.DNSServerAddressOptions.Build()
	if serverAddr.Port == 0 {
		serverAddr.Port = 53
	}
	if !serverAddr.IsValid() {
		return nil, E.New("invalid server address: ", serverAddr)
	}
	enableConnReuse := options.Reuse
	if options.Pipeline {
		enableConnReuse = true
	}
	var poolIdleTimeout time.Duration
	if options.DisableTCPKeepAlive {
		poolIdleTimeout = 2 * time.Minute
	} else {
		var keepAliveIdle, keepAliveInterval time.Duration
		if options.TCPKeepAlive != 0 {
			keepAliveIdle = time.Duration(options.TCPKeepAlive)
		} else {
			keepAliveIdle = C.TCPKeepAliveInitial
		}
		if options.TCPKeepAliveInterval != 0 {
			keepAliveInterval = time.Duration(options.TCPKeepAliveInterval)
		} else {
			keepAliveInterval = C.TCPKeepAliveInterval
		}
		poolIdleTimeout = keepAliveIdle + keepAliveInterval
	}
	maxQueries := max(options.MaxQueries, 0)
	if !options.Pipeline && maxQueries > 0 {
		maxQueries = 0
	}
	transport := &TCPTransport{
		TransportAdapter: dns.NewTransportAdapterWithRemoteOptions(C.DNSTypeTCP, tag, options.RemoteDNSServerOptions),
		dialer:           transportDialer,
		serverAddr:       serverAddr,
		pipelinePool: pipelinePool{
			logger:           logger,
			enablePipeline:   options.Pipeline,
			idleTimeout:      poolIdleTimeout,
			disableKeepAlive: options.DisableTCPKeepAlive,
			maxQueries:       maxQueries,
		},
	}
	if enableConnReuse {
		transport.connections = newReuseableDNSConnPool(0)
	}
	return transport, nil
}

func (t *TCPTransport) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	return dialer.InitializeDetour(t.dialer)
}

func (t *TCPTransport) Close() error {
	return t.pipelinePool.closePool()
}

func (t *TCPTransport) Reset() {
	t.pipelinePool.resetPool()
}

func (t *TCPTransport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	if t.connections == nil {
		return t.createNewConnection(ctx, message)
	}
	return t.pipelinePool.exchange(ctx, message, t.createNewConnection)
}

func (t *TCPTransport) createNewConnection(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	if t.connections != nil {
		conn, _, err := t.connections.Acquire(ctx, func(ctx context.Context) (*reuseableDNSConn, error) {
			rawConn, err := t.dialer.DialContext(ctx, N.NetworkTCP, t.serverAddr)
			if err != nil {
				return nil, E.Cause(err, "dial TCP connection")
			}
			var connIdleTimeout time.Duration
			if t.disableKeepAlive {
				connIdleTimeout = t.idleTimeout
			}
			return newReuseableDNSConn(rawConn, t.logger, t.enablePipeline, connIdleTimeout, t.maxQueries, t.connections, t, deadline.NeedAdditionalReadDeadline(rawConn)), nil
		})
		if err != nil {
			return nil, err
		}
		if t.enablePipeline && t.maxQueries > 0 {
			t.addActiveConn(conn)
		}
		return conn.Exchange(ctx, message)
	}
	rawConn, err := t.dialer.DialContext(ctx, N.NetworkTCP, t.serverAddr)
	if err != nil {
		return nil, E.Cause(err, "dial TCP connection")
	}
	conn := newReuseableDNSConn(rawConn, t.logger, t.enablePipeline, 0, t.maxQueries, nil, t, deadline.NeedAdditionalReadDeadline(rawConn))
	defer conn.Close()
	return conn.Exchange(ctx, message)
}

func setConnDeadline(ctx context.Context, conn net.Conn, needClose bool) func() {
	if needClose {
		stop := context.AfterFunc(ctx, func() {
			conn.Close()
		})
		return func() { stop() }
	}
	if d, ok := ctx.Deadline(); ok {
		conn.SetDeadline(d)
		return func() { conn.SetDeadline(time.Time{}) }
	}
	return func() {}
}

func ReadMessage(reader io.Reader) (*mDNS.Msg, error) {
	var responseLen uint16
	err := binary.Read(reader, binary.BigEndian, &responseLen)
	if err != nil {
		return nil, err
	}
	if responseLen < 10 {
		return nil, mDNS.ErrShortRead
	}
	buffer := buf.NewSize(int(responseLen))
	defer buffer.Release()
	_, err = buffer.ReadFullFrom(reader, int(responseLen))
	if err != nil {
		return nil, err
	}
	var message mDNS.Msg
	err = message.Unpack(buffer.Bytes())
	return &message, err
}

func WriteMessage(writer io.Writer, messageId uint16, message *mDNS.Msg) error {
	requestLen := message.Len()
	buffer := buf.NewSize(3 + requestLen)
	defer buffer.Release()
	common.Must(binary.Write(buffer, binary.BigEndian, uint16(requestLen)))
	exMessage := *message
	exMessage.Id = messageId
	exMessage.Compress = true
	rawMessage, err := exMessage.PackBuffer(buffer.FreeBytes())
	if err != nil {
		return err
	}
	buffer.Truncate(2 + len(rawMessage))
	return common.Error(writer.Write(buffer.Bytes()))
}

type dnsCallback struct {
	access  sync.Mutex
	message *mDNS.Msg
	done    chan struct{}
}

type reuseableDNSConn struct {
	net.Conn
	logger            logger.ContextLogger
	access            sync.RWMutex
	done              chan struct{}
	closeOnce         sync.Once
	err               error
	queryId           uint16
	callbacks         map[uint16]*dnsCallback
	writeLock         sync.Mutex
	startReadOnce     sync.Once
	enablePipeline    bool
	needDeadlineClose bool
	activeQueries     atomic.Int32
	maxQueries        int
	pool              *ConnPool[*reuseableDNSConn]
	transport         dnsTransportManager
	idleTimeout       time.Duration
	idleTimer         *time.Timer
}

func newReuseableDNSConn(conn net.Conn, logger logger.ContextLogger, enablePipeline bool, idleTimeout time.Duration, maxQueries int, pool *ConnPool[*reuseableDNSConn], transport dnsTransportManager, needDeadlineClose bool) *reuseableDNSConn {
	c := &reuseableDNSConn{
		Conn:              conn,
		logger:            logger,
		done:              make(chan struct{}),
		callbacks:         make(map[uint16]*dnsCallback),
		enablePipeline:    enablePipeline,
		needDeadlineClose: needDeadlineClose,
		maxQueries:        maxQueries,
		pool:              pool,
		transport:         transport,
		idleTimeout:       idleTimeout,
	}
	if idleTimeout > 0 {
		c.idleTimer = time.AfterFunc(idleTimeout, func() {
			c.closeWithError(E.New("connection idle timeout"))
		})
	}
	return c
}

func (c *reuseableDNSConn) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	c.activeQueries.Add(1)
	return c.exchangeWithCleanup(ctx, message, true)
}

func (c *reuseableDNSConn) exchangeWithoutIncrement(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	return c.exchangeWithCleanup(ctx, message, true)
}

func (c *reuseableDNSConn) exchangeWithCleanup(ctx context.Context, message *mDNS.Msg, resetTimer bool) (*mDNS.Msg, error) {
	if resetTimer && c.enablePipeline && c.idleTimer != nil {
		c.idleTimer.Reset(c.idleTimeout)
	}
	defer func() {
		if resetTimer && !c.enablePipeline && c.idleTimer != nil {
			c.idleTimer.Reset(c.idleTimeout)
		}
		newCount := c.activeQueries.Add(-1)
		if newCount == 0 && c.pool != nil {
			if c.enablePipeline && c.maxQueries > 0 && c.transport != nil {
				c.transport.removeActiveConn(c)
			}
			select {
			case <-c.done:
				c.pool.Invalidate(c, c.err)
			default:
				c.pool.Release(c, true)
			}
		}
	}()

	if !c.enablePipeline {
		c.writeLock.Lock()
		defer c.writeLock.Unlock()
		defer setConnDeadline(ctx, c.Conn, c.needDeadlineClose)()

		err := WriteMessage(c.Conn, 0, message)
		if err != nil {
			wrappedErr := E.Cause(err, "write request")
			c.closeWithError(wrappedErr)
			return nil, wrappedErr
		}
		response, err := ReadMessage(c.Conn)
		if err != nil {
			wrappedErr := E.Cause(err, "read response")
			c.closeWithError(wrappedErr)
			return nil, wrappedErr
		}
		return response, nil
	}

	c.startReadOnce.Do(func() {
		go c.recvLoop()
	})

	c.access.Lock()
	c.queryId++
	messageId := c.queryId
	callback := &dnsCallback{
		done: make(chan struct{}),
	}
	c.callbacks[messageId] = callback
	c.access.Unlock()

	defer func() {
		c.access.Lock()
		delete(c.callbacks, messageId)
		c.access.Unlock()
	}()

	c.writeLock.Lock()
	err := WriteMessage(c.Conn, messageId, message)
	c.writeLock.Unlock()
	if err != nil {
		wrappedErr := E.Cause(err, "write request")
		c.closeWithError(wrappedErr)
		return nil, wrappedErr
	}
	originalId := message.Id
	select {
	case <-callback.done:
		if callback.message != nil {
			callback.message.Id = originalId
			return callback.message, nil
		}
		return nil, E.New("response is nil")
	case <-c.done:
		return nil, c.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (c *reuseableDNSConn) recvLoop() {
	var lastRecvId uint16
	for {
		message, err := ReadMessage(c.Conn)
		if err != nil {
			wrappedErr := E.Cause(err, "read response")
			c.closeWithError(wrappedErr)
			return
		}

		c.access.RLock()
		callback, loaded := c.callbacks[message.Id]
		c.access.RUnlock()

		if !loaded {
			if c.logger != nil {
				c.logger.Debug("received response for unknown message ID: ", message.Id)
			}
			continue
		}

		if c.enablePipeline && c.transport != nil && !c.transport.isPipelineDetected() {
			consecutivePtr, outOfOrderPtr, totalPtr := c.transport.getDetectionCounters()
			totalResp := atomic.AddInt32(totalPtr, 1)

			detected := false
			if totalResp > 1 {
				diff := uint16(message.Id) - uint16(lastRecvId)
				if diff > 0x8000 {
					outOfOrder := atomic.AddInt32(outOfOrderPtr, 1)
					consecutive := atomic.AddInt32(consecutivePtr, 1)

					if consecutive >= 3 || (totalResp >= 10 && outOfOrder*10 > totalResp*3) {
						detected = true
						if c.transport.markPipelineDetected() && c.logger != nil {
							c.logger.Debug("server supports pipelining")
						}
					}
				} else {
					atomic.StoreInt32(consecutivePtr, 0)
				}
			}

			if !detected && totalResp >= 50 {
				detected = true
				c.transport.markPipelineDetected()
			}

			if detected {
				atomic.StoreInt32(consecutivePtr, 0)
				atomic.StoreInt32(outOfOrderPtr, 0)
				atomic.StoreInt32(totalPtr, 0)
			}
		}
		lastRecvId = message.Id
		callback.access.Lock()
		select {
		case <-callback.done:
		default:
			callback.message = message
			close(callback.done)
		}
		callback.access.Unlock()
	}
}

func (c *reuseableDNSConn) IsOverMaxQueries() bool {
	if c.maxQueries <= 0 {
		return false
	}
	return c.activeQueries.Load() >= int32(c.maxQueries)
}

func (c *reuseableDNSConn) closeWithError(err error) {
	c.closeOnce.Do(func() {
		if c.idleTimer != nil {
			c.idleTimer.Stop()
		}
		c.err = err
		close(c.done)
		c.Conn.Close()
	})
}

func (c *reuseableDNSConn) Close() {
	c.closeWithError(net.ErrClosed)
}
