//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"io"
	"net"
	"os"
	"sync"
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
	cache   *freelru.Cache[udpSessionKey, *udpNATConn]
	handler N.UDPConnectionHandlerEx
	prepare udpNATPrepareFunc
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
	cache.SetOnEvict(func(_ udpSessionKey, conn *udpNATConn) {
		_ = conn.Close()
	})
	return &udpNATService{
		cache:   cache,
		handler: handler,
		prepare: prepare,
	}
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
	conn, _, loaded := s.cache.GetAndRefreshOrAdd(key, func() (*udpNATConn, bool) {
		ok, ctx, writer, onClose := s.prepare(key, source, destination, userData)
		if !ok {
			return nil, false
		}
		newConn := &udpNATConn{
			cache:        s.cache,
			key:          key,
			writer:       writer,
			localAddr:    source,
			packetChan:   make(chan *N.PacketBuffer, 64),
			doneChan:     make(chan struct{}),
			readDeadline: pipe.MakeDeadline(),
		}
		go s.handler.NewPacketConnectionEx(ctx, newConn, source, destination, onClose)
		return newConn, true
	})
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
		handler.NewPacketEx(buffer, destination)
		return
	}
	c.enqueuePacketLocked(buffer, destination)
	c.handlerAccess.RUnlock()
}

func (c *udpNATConn) newPacketBuffer(buffer *buf.Buffer, destination M.Socksaddr) {
	c.handlerAccess.RLock()
	handler := c.handler
	if handler != nil {
		buffer = c.readWaitOptions.Copy(buffer)
		c.handlerAccess.RUnlock()
		handler.NewPacketEx(buffer, destination)
		return
	}
	c.enqueuePacketLocked(buffer, destination)
	c.handlerAccess.RUnlock()
}

// enqueuePacketLocked requires handlerAccess to remain read-locked so
// SetHandler cannot finish draining the queue before this packet is visible.
func (c *udpNATConn) enqueuePacketLocked(buffer *buf.Buffer, destination M.Socksaddr) {
	packet := N.NewPacketBuffer()
	*packet = N.PacketBuffer{
		Buffer:      buffer,
		Destination: destination,
	}
	select {
	case c.packetChan <- packet:
	default:
		packet.Buffer.Release()
		N.PutPacketBuffer(packet)
	}
}

func (s *udpNATService) Purge() {
	s.cache.Purge()
}

type udpNATConn struct {
	cache           *freelru.Cache[udpSessionKey, *udpNATConn]
	key             udpSessionKey
	writer          N.PacketWriter
	localAddr       M.Socksaddr
	handlerAccess   sync.RWMutex
	handler         N.UDPHandlerEx
	packetChan      chan *N.PacketBuffer
	closeOnce       sync.Once
	doneChan        chan struct{}
	readDeadline    pipe.Deadline
	readWaitOptions N.ReadWaitOptions
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
	c.handler = handler
	c.readWaitOptions = N.NewReadWaitOptions(nil, handler)
	readWaitOptions := c.readWaitOptions
	c.handlerAccess.Unlock()
	for {
		select {
		case packet := <-c.packetChan:
			buffer := readWaitOptions.Copy(packet.Buffer)
			handler.NewPacketEx(buffer, packet.Destination)
			N.PutPacketBuffer(packet)
		default:
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
	return c.cache.UpdateLifetime(c.key, c, timeout)
}

func (c *udpNATConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.doneChan)
		_ = common.Close(c.handler)
	})
	return nil
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
