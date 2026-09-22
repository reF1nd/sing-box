//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/canceler"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/pipe"
	"github.com/sagernet/sing/contrab/freelru"
	"github.com/sagernet/sing/contrab/maphash"
)

type udpNATPrepareFunc func(
	key udpSessionKey,
	source M.Socksaddr,
	destination M.Socksaddr,
	userData any,
) (bool, context.Context, N.PacketWriter, N.CloseHandlerFunc)

// udpNATService is local to the eBPF inbound because its session identity is
// kernel-flow-specific. A source address alone is ambiguous across socket
// cookies, ingress interfaces, and local/shared data planes.
type udpNATService struct {
	cache                          *freelru.Cache[udpSessionKey, *udpNATConn]
	handler                        N.UDPConnectionHandlerEx
	prepare                        udpNATPrepareFunc
	timeout                        time.Duration
	cleanup                        *udpNATCleanupQueue
	cleanupDone                    chan struct{}
	cleanupWait                    sync.WaitGroup
	releaseAccess                  sync.Mutex
	releaseConnections             map[uint64]*udpNATConn
	pendingReleases                map[uint64]time.Time
	queueDrops                     atomic.Uint64
	socketReleaseEvents            atomic.Uint64
	socketReleaseMatched           atomic.Uint64
	pendingReleaseCapacityRejected atomic.Uint64
	closed                         atomic.Bool
	closeOnce                      sync.Once
}

func newUDPNATService(
	handler N.UDPConnectionHandlerEx,
	prepare udpNATPrepareFunc,
	timeout time.Duration,
) *udpNATService {
	if timeout == 0 {
		panic("invalid timeout")
	}
	cache := common.Must1(freelru.New[udpSessionKey, *udpNATConn](
		1024,
		maphash.NewHasher[udpSessionKey]().Hash32,
		false,
	))
	cache.SetLifetime(timeout)
	cache.SetHealthCheck(func(_ udpSessionKey, conn *udpNATConn) bool {
		select {
		case <-conn.doneChan:
			return false
		default:
			return true
		}
	})
	service := &udpNATService{
		cache:              cache,
		handler:            handler,
		prepare:            prepare,
		timeout:            timeout,
		cleanupDone:        make(chan struct{}),
		releaseConnections: make(map[uint64]*udpNATConn),
		pendingReleases:    make(map[uint64]time.Time),
	}
	service.cleanup = newUDPNATCleanupQueue(service)
	cache.SetOnEvict(func(_ udpSessionKey, conn *udpNATConn) {
		conn.closeFromCache()
	})
	service.cleanupWait.Add(1)
	go service.cleanupLoop()
	return service
}

func (s *udpNATService) NewPacket(
	key udpSessionKey,
	bufferSlices [][]byte,
	source M.Socksaddr,
	destination M.Socksaddr,
	userData any,
) {
	conn, loaded := s.connection(key, source, destination, userData)
	if !loaded {
		return
	}
	conn.newPacket(bufferSlices, destination)
}

// NewPacketBuffer takes ownership of buffer, including when preparing the
// connection fails or its receive queue is full.
func (s *udpNATService) NewPacketBuffer(
	key udpSessionKey,
	buffer *buf.Buffer,
	source M.Socksaddr,
	destination M.Socksaddr,
	userData any,
) {
	conn, loaded := s.connection(key, source, destination, userData)
	if !loaded {
		buffer.Release()
		return
	}
	conn.newPacketBuffer(buffer, destination)
}

func (s *udpNATService) connection(
	key udpSessionKey,
	source M.Socksaddr,
	destination M.Socksaddr,
	userData any,
) (*udpNATConn, bool) {
	if s.closed.Load() {
		return nil, false
	}
	var (
		newContext context.Context
		newOnClose N.CloseHandlerFunc
	)
	conn, updated, loaded := s.cache.GetAndRefreshOrAdd(key, func() (*udpNATConn, bool) {
		ok, ctx, writer, onClose := s.prepare(key, source, destination, userData)
		if !ok {
			return nil, false
		}
		newConn := &udpNATConn{
			service:      s,
			cache:        s.cache,
			key:          key,
			writer:       writer,
			localAddr:    source,
			packetChan:   make(chan *N.PacketBuffer, 64),
			doneChan:     make(chan struct{}),
			readDeadline: pipe.MakeDeadline(),
		}
		newConn.cleanupEntry = &udpNATCleanupEntry{
			conn:  newConn,
			index: -1,
		}
		newContext = ctx
		newOnClose = onClose
		return newConn, true
	})
	if !loaded {
		return nil, false
	}
	if s.closed.Load() {
		s.cache.Remove(key)
		if !updated && newOnClose != nil {
			newOnClose(net.ErrClosed)
		}
		return nil, false
	}
	if !updated {
		if !s.registerReleaseConnection(conn) {
			s.cache.Remove(key)
			if newOnClose != nil {
				newOnClose(net.ErrClosed)
			}
			return nil, false
		}
		s.cleanup.addOrUpdate(conn.cleanupEntry, time.Now().Add(s.timeout))
		if conn.isClosed() {
			s.cache.Remove(key)
			if newOnClose != nil {
				newOnClose(net.ErrClosed)
			}
			return nil, false
		}
		go s.handler.NewPacketConnectionEx(newContext, conn, source, destination, newOnClose)
	}
	return conn, loaded
}

func (c *udpNATConn) newPacket(bufferSlices [][]byte, destination M.Socksaddr) {
	c.handlerAccess.RLock()
	readWaitOptions := c.readWaitOptions
	handler := c.handler
	dataLen := 0
	for _, bufferSlice := range bufferSlices {
		dataLen += len(bufferSlice)
	}
	buffer := readWaitOptions.NewBufferSize(dataLen)
	for _, bufferSlice := range bufferSlices {
		_, _ = buffer.Write(bufferSlice)
	}
	readWaitOptions.PostReturn(buffer)
	if handler != nil {
		c.handlerAccess.RUnlock()
		if c.isClosed() {
			buffer.Release()
			return
		}
		handler.NewPacketEx(buffer, destination)
		return
	}
	c.packetAccess.RLock()
	select {
	case <-c.doneChan:
		c.packetAccess.RUnlock()
		c.handlerAccess.RUnlock()
		buffer.Release()
		return
	default:
	}
	c.enqueuePacketLocked(buffer, destination)
	c.packetAccess.RUnlock()
	c.handlerAccess.RUnlock()
}

func (c *udpNATConn) newPacketBuffer(buffer *buf.Buffer, destination M.Socksaddr) {
	c.handlerAccess.RLock()
	handler := c.handler
	if handler != nil {
		buffer = c.readWaitOptions.Copy(buffer)
		c.handlerAccess.RUnlock()
		if c.isClosed() {
			buffer.Release()
			return
		}
		handler.NewPacketEx(buffer, destination)
		return
	}
	c.packetAccess.RLock()
	select {
	case <-c.doneChan:
		c.packetAccess.RUnlock()
		c.handlerAccess.RUnlock()
		buffer.Release()
		return
	default:
	}
	c.enqueuePacketLocked(buffer, destination)
	c.packetAccess.RUnlock()
	c.handlerAccess.RUnlock()
}

// enqueuePacketLocked requires handlerAccess and packetAccess to remain
// read-locked so SetHandler cannot finish draining the queue before this packet
// is visible and Close cannot finish draining before it is enqueued.
func (c *udpNATConn) enqueuePacketLocked(buffer *buf.Buffer, destination M.Socksaddr) {
	packet := N.NewPacketBuffer()
	*packet = N.PacketBuffer{
		Buffer:      buffer,
		Destination: destination,
	}
	select {
	case c.packetChan <- packet:
	default:
		c.service.queueDrops.Add(1)
		packet.Buffer.Release()
		N.PutPacketBuffer(packet)
	}
}

func (s *udpNATService) Purge() {
	s.cache.Purge()
}

const (
	udpNATPendingReleaseCapacity = 1024
	udpNATPendingReleaseTTL      = 5 * time.Second
)

// ReleaseSocket closes the local-cgroup UDP session associated with a socket
// cookie. A bounded short-lived pending set covers the race where sock_release
// reaches userspace before the redirected datagram creates its NAT session.
// TC and shared sessions are deliberately excluded: they keep deadline-based
// cleanup and do not install a cgroup socket-release observer.
func (s *udpNATService) ReleaseSocket(socketCookie uint64) {
	if socketCookie == 0 || s.closed.Load() {
		return
	}
	s.socketReleaseEvents.Add(1)
	now := time.Now()
	s.releaseAccess.Lock()
	conn := s.releaseConnections[socketCookie]
	if conn != nil {
		delete(s.releaseConnections, socketCookie)
		s.socketReleaseMatched.Add(1)
	} else {
		for cookie, expiry := range s.pendingReleases {
			if !expiry.After(now) {
				delete(s.pendingReleases, cookie)
			}
		}
		if len(s.pendingReleases) < udpNATPendingReleaseCapacity {
			s.pendingReleases[socketCookie] = now.Add(udpNATPendingReleaseTTL)
		} else {
			s.pendingReleaseCapacityRejected.Add(1)
		}
	}
	s.releaseAccess.Unlock()
	if conn != nil {
		_ = conn.Close()
	}
}

func (s *udpNATService) diagnostics() UDPNATDiagnostics {
	if s == nil {
		return UDPNATDiagnostics{}
	}
	metrics := s.cache.Metrics()
	return UDPNATDiagnostics{
		ActiveSessions:                 s.cache.Len(),
		CreatedSessions:                metrics.Inserts,
		CapacityEvictions:              metrics.Evictions,
		QueueDrops:                     s.queueDrops.Load(),
		SocketReleaseEvents:            s.socketReleaseEvents.Load(),
		SocketReleaseMatched:           s.socketReleaseMatched.Load(),
		PendingReleaseCapacityRejected: s.pendingReleaseCapacityRejected.Load(),
	}
}

func (s *udpNATService) registerReleaseConnection(conn *udpNATConn) bool {
	if conn == nil || conn.key.Scope != udpSessionScopeLocalCgroup || conn.key.SocketCookie == 0 {
		return true
	}
	now := time.Now()
	s.releaseAccess.Lock()
	expiry, released := s.pendingReleases[conn.key.SocketCookie]
	if released {
		delete(s.pendingReleases, conn.key.SocketCookie)
		released = expiry.After(now)
	}
	if !released {
		s.releaseConnections[conn.key.SocketCookie] = conn
	}
	s.releaseAccess.Unlock()
	return !released
}

func (s *udpNATService) unregisterReleaseConnection(conn *udpNATConn) {
	if conn == nil || conn.key.Scope != udpSessionScopeLocalCgroup || conn.key.SocketCookie == 0 {
		return
	}
	s.releaseAccess.Lock()
	if s.releaseConnections[conn.key.SocketCookie] == conn {
		delete(s.releaseConnections, conn.key.SocketCookie)
	}
	s.releaseAccess.Unlock()
}

func (s *udpNATService) Close() error {
	s.closeOnce.Do(func() {
		s.closed.Store(true)
		close(s.cleanupDone)
		s.cleanupWait.Wait()
		s.cache.Purge()
		s.cleanup.clear()
		s.releaseAccess.Lock()
		clear(s.releaseConnections)
		clear(s.pendingReleases)
		s.releaseAccess.Unlock()
	})
	return nil
}

type udpNATConn struct {
	service         *udpNATService
	cache           *freelru.Cache[udpSessionKey, *udpNATConn]
	key             udpSessionKey
	writer          N.PacketWriter
	localAddr       M.Socksaddr
	handlerAccess   sync.RWMutex
	handler         N.UDPHandlerEx
	packetAccess    sync.RWMutex
	packetChan      chan *N.PacketBuffer
	closeOnce       sync.Once
	doneChan        chan struct{}
	readDeadline    pipe.Deadline
	readWaitOptions N.ReadWaitOptions
	cleanupEntry    *udpNATCleanupEntry
}

var (
	_ N.PacketConn                 = (*udpNATConn)(nil)
	_ canceler.PacketConn          = (*udpNATConn)(nil)
	_ N.PacketBatchReadWaitCreator = (*udpNATConn)(nil)
	_ N.PacketBatchWriteCreator    = (*udpNATConn)(nil)
)

func (c *udpNATConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	select {
	case packet := <-c.packetChan:
		_, err := buffer.ReadOnceFrom(packet.Buffer)
		destination := packet.Destination
		packet.Buffer.Release()
		N.PutPacketBuffer(packet)
		return destination, err
	case <-c.doneChan:
		return M.Socksaddr{}, io.ErrClosedPipe
	case <-c.readDeadline.Wait():
		return M.Socksaddr{}, os.ErrDeadlineExceeded
	}
}

func (c *udpNATConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	return c.writer.WritePacket(buffer, destination)
}

func (c *udpNATConn) CreatePacketBatchWriter() (N.PacketBatchWriter, bool) {
	if writer, loaded := c.writer.(N.PacketBatchWriter); loaded {
		return writer, true
	}
	if creator, loaded := c.writer.(N.PacketBatchWriteCreator); loaded {
		return creator.CreatePacketBatchWriter()
	}
	return nil, false
}

func (c *udpNATConn) InitializeReadWaiter(options N.ReadWaitOptions) bool {
	c.handlerAccess.Lock()
	c.readWaitOptions = options
	c.handlerAccess.Unlock()
	return false
}

func (c *udpNATConn) WaitReadPacket() (*buf.Buffer, M.Socksaddr, error) {
	select {
	case packet := <-c.packetChan:
		buffer := c.readWaitOptions.Copy(packet.Buffer)
		destination := packet.Destination
		N.PutPacketBuffer(packet)
		return buffer, destination, nil
	case <-c.doneChan:
		return nil, M.Socksaddr{}, io.ErrClosedPipe
	case <-c.readDeadline.Wait():
		return nil, M.Socksaddr{}, os.ErrDeadlineExceeded
	}
}

func (c *udpNATConn) CreatePacketBatchReadWaiter() (N.PacketBatchReadWaiter, bool) {
	return c, true
}

func (c *udpNATConn) WaitReadPackets() ([]*buf.Buffer, []M.Socksaddr, error) {
	buffer, destination, err := c.WaitReadPacket()
	if err != nil {
		return nil, nil, err
	}
	batchSize := c.readWaitOptions.BatchSize
	if batchSize <= 0 {
		batchSize = 1
	}
	buffers := []*buf.Buffer{buffer}
	destinations := []M.Socksaddr{destination}
	for len(buffers) < batchSize {
		select {
		case packet := <-c.packetChan:
			buffers = append(buffers, c.readWaitOptions.Copy(packet.Buffer))
			destinations = append(destinations, packet.Destination)
			N.PutPacketBuffer(packet)
		default:
			return buffers, destinations, nil
		}
	}
	return buffers, destinations, nil
}

func (c *udpNATConn) SetHandler(handler N.UDPHandlerEx) {
	c.handlerAccess.Lock()
	c.packetAccess.Lock()
	select {
	case <-c.doneChan:
		c.packetAccess.Unlock()
		c.handlerAccess.Unlock()
		_ = common.Close(handler)
		return
	default:
	}
	c.handler = handler
	c.readWaitOptions = N.NewReadWaitOptions(nil, handler)
	readWaitOptions := c.readWaitOptions
	var queuedPackets []*N.PacketBuffer
	for {
		select {
		case packet := <-c.packetChan:
			queuedPackets = append(queuedPackets, packet)
		default:
			c.packetAccess.Unlock()
			c.handlerAccess.Unlock()
			for _, packet := range queuedPackets {
				if c.isClosed() {
					packet.Buffer.Release()
					N.PutPacketBuffer(packet)
					continue
				}
				buffer := readWaitOptions.Copy(packet.Buffer)
				handler.NewPacketEx(buffer, packet.Destination)
				N.PutPacketBuffer(packet)
			}
			return
		}
	}
}

func (c *udpNATConn) Timeout() time.Duration {
	conn, lifetime, loaded := c.cache.PeekWithLifetime(c.key)
	if !loaded || conn != c {
		return 0
	}
	return time.Until(lifetime)
}

func (c *udpNATConn) SetTimeout(timeout time.Duration) bool {
	updated := c.cache.UpdateLifetime(c.key, c, timeout)
	if !updated {
		return false
	}
	if timeout == 0 {
		c.service.cleanup.remove(c.cleanupEntry)
	} else {
		c.service.cleanup.addOrUpdate(c.cleanupEntry, time.Now().Add(timeout))
	}
	return true
}

func (c *udpNATConn) Close() error {
	c.close()
	if !c.service.closed.Load() {
		c.service.cleanup.addOrUpdate(c.cleanupEntry, time.Now())
	}
	return nil
}

func (c *udpNATConn) close() {
	c.closeOnce.Do(func() {
		c.service.unregisterReleaseConnection(c)
		c.handlerAccess.Lock()
		c.packetAccess.Lock()
		for {
			select {
			case packet := <-c.packetChan:
				packet.Buffer.Release()
				N.PutPacketBuffer(packet)
			default:
				handler := c.handler
				close(c.doneChan)
				c.packetAccess.Unlock()
				c.handlerAccess.Unlock()
				_ = common.Close(handler)
				return
			}
		}
	})
}

func (c *udpNATConn) closeFromCache() {
	c.close()
	c.service.cleanup.remove(c.cleanupEntry)
}

func (c *udpNATConn) isClosed() bool {
	select {
	case <-c.doneChan:
		return true
	default:
		return false
	}
}

func (c *udpNATConn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *udpNATConn) RemoteAddr() net.Addr {
	return M.Socksaddr{}
}

func (c *udpNATConn) SetDeadline(time.Time) error {
	return os.ErrInvalid
}

func (c *udpNATConn) SetReadDeadline(deadline time.Time) error {
	c.readDeadline.Set(deadline)
	return nil
}

func (c *udpNATConn) SetWriteDeadline(time.Time) error {
	return os.ErrInvalid
}

func (c *udpNATConn) Upstream() any {
	return c.writer
}
