package snell

import (
	"container/heap"
	"context"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	snellprotocol "github.com/sagernet/sing-snell"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/pipe"
)

type quicProxyNATPrepareFunc func(source M.Socksaddr, destination M.Socksaddr, session *snellprotocol.QUICProxySession) (context.Context, N.PacketWriter)

type quicProxyNATEntry struct {
	key       netip.AddrPort
	source    M.Socksaddr
	session   *snellprotocol.QUICProxySession
	conn      *quicProxyNATConn
	expiresAt time.Time
	index     int
}

func (e *quicProxyNATEntry) close() {
	e.conn.closeInternal()
}

type quicProxyNATHeap []*quicProxyNATEntry

func (h quicProxyNATHeap) Len() int { return len(h) }
func (h quicProxyNATHeap) Less(i, j int) bool {
	return h[i].expiresAt.Before(h[j].expiresAt)
}
func (h quicProxyNATHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].index = i
	h[j].index = j
}
func (h *quicProxyNATHeap) Push(value any) {
	entry := value.(*quicProxyNATEntry)
	entry.index = len(*h)
	*h = append(*h, entry)
}
func (h *quicProxyNATHeap) Pop() any {
	old := *h
	last := len(old) - 1
	entry := old[last]
	old[last] = nil
	entry.index = -1
	*h = old[:last]
	return entry
}

type quicProxyNATService struct {
	handler N.UDPConnectionHandlerEx
	prepare quicProxyNATPrepareFunc
	timeout time.Duration
	access  sync.Mutex
	entries map[netip.AddrPort]*quicProxyNATEntry
	queue   quicProxyNATHeap
	wake    chan struct{}
	done    chan struct{}
	closed  bool
}

func newQUICProxyNATService(handler N.UDPConnectionHandlerEx, prepare quicProxyNATPrepareFunc, timeout time.Duration) *quicProxyNATService {
	service := &quicProxyNATService{
		handler: handler,
		prepare: prepare,
		timeout: timeout,
		entries: make(map[netip.AddrPort]*quicProxyNATEntry),
		wake:    make(chan struct{}, 1),
		done:    make(chan struct{}),
	}
	go service.run()
	return service
}

func (s *quicProxyNATService) Session(source M.Socksaddr) (*quicProxyNATEntry, bool) {
	key := source.AddrPort()
	now := time.Now()
	s.access.Lock()
	entry, loaded := s.entries[key]
	if loaded && !entry.expiresAt.After(now) {
		s.removeLocked(entry)
		loaded = false
	}
	s.access.Unlock()
	if entry != nil && !loaded {
		entry.close()
	}
	if !loaded {
		return nil, false
	}
	return entry, true
}

func (s *quicProxyNATService) NewPacket(entry *quicProxyNATEntry, payload []byte) bool {
	now := time.Now()
	s.access.Lock()
	loaded := s.entries[entry.key] == entry
	if loaded && !entry.expiresAt.After(now) {
		s.removeLocked(entry)
		loaded = false
	} else if loaded {
		entry.expiresAt = now.Add(s.timeout)
		heap.Fix(&s.queue, entry.index)
		if len(payload) > 0 {
			entry.conn.enqueue(payload, entry.session.Target())
		}
	}
	s.access.Unlock()
	if !loaded {
		entry.close()
		return false
	}
	return true
}

func (s *quicProxyNATService) NewSession(source M.Socksaddr, session *snellprotocol.QUICProxySession, payload []byte) bool {
	key := source.AddrPort()
	now := time.Now()
	var expired *quicProxyNATEntry
	s.access.Lock()
	if s.closed {
		s.access.Unlock()
		return false
	}
	if existing, loaded := s.entries[key]; loaded {
		if existing.expiresAt.After(now) {
			s.access.Unlock()
			return false
		}
		s.removeLocked(existing)
		expired = existing
	}
	entry := &quicProxyNATEntry{
		key:       key,
		source:    source,
		session:   session,
		expiresAt: now.Add(s.timeout),
	}
	ctx, conn := s.newConnection(entry)
	entry.conn = conn
	conn.enqueue(payload, session.Target())
	wake := len(s.queue) == 0
	s.entries[key] = entry
	heap.Push(&s.queue, entry)
	s.access.Unlock()
	if expired != nil {
		expired.close()
	}
	if wake {
		s.notify()
	}
	go s.handleConnection(ctx, entry, conn)
	return true
}

// The caller must hold s.access.
func (s *quicProxyNATService) newConnection(entry *quicProxyNATEntry) (context.Context, *quicProxyNATConn) {
	ctx, writer := s.prepare(entry.source, entry.session.Target(), entry.session)
	return ctx, &quicProxyNATConn{
		service:      s,
		entry:        entry,
		writer:       writer,
		packetChan:   make(chan quicProxyNATPacket, 64),
		done:         make(chan struct{}),
		readDeadline: pipe.MakeDeadline(),
	}
}

func (s *quicProxyNATService) handleConnection(ctx context.Context, entry *quicProxyNATEntry, conn *quicProxyNATConn) {
	s.handler.NewPacketConnectionEx(ctx, conn, entry.source, entry.session.Target(), func(error) {
		s.remove(entry)
	})
}

func (s *quicProxyNATService) Len() int {
	s.access.Lock()
	defer s.access.Unlock()
	return len(s.entries)
}

func (s *quicProxyNATService) Close() {
	s.access.Lock()
	if s.closed {
		s.access.Unlock()
		<-s.done
		return
	}
	s.closed = true
	entries := make([]*quicProxyNATEntry, 0, len(s.entries))
	for _, entry := range s.entries {
		entries = append(entries, entry)
	}
	clear(s.entries)
	s.queue = nil
	s.access.Unlock()
	for _, entry := range entries {
		entry.close()
	}
	s.notify()
	<-s.done
}

func (s *quicProxyNATService) remove(entry *quicProxyNATEntry) {
	s.access.Lock()
	if s.entries[entry.key] == entry {
		s.removeLocked(entry)
	}
	s.access.Unlock()
	entry.close()
}

func (s *quicProxyNATService) removeLocked(entry *quicProxyNATEntry) {
	delete(s.entries, entry.key)
	if entry.index >= 0 {
		heap.Remove(&s.queue, entry.index)
	}
}

func (s *quicProxyNATService) run() {
	defer close(s.done)
	for {
		s.access.Lock()
		if s.closed {
			s.access.Unlock()
			return
		}
		now := time.Now()
		var expired []*quicProxyNATEntry
		for len(s.queue) > 0 && !s.queue[0].expiresAt.After(now) {
			entry := heap.Pop(&s.queue).(*quicProxyNATEntry)
			delete(s.entries, entry.key)
			expired = append(expired, entry)
		}
		if len(s.queue) == 0 {
			s.access.Unlock()
			for _, entry := range expired {
				entry.close()
			}
			<-s.wake
			continue
		}
		wait := time.Until(s.queue[0].expiresAt)
		s.access.Unlock()
		for _, entry := range expired {
			entry.close()
		}
		if wait < 0 {
			wait = 0
		}
		timer := time.NewTimer(wait)
		select {
		case <-timer.C:
		case <-s.wake:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
		}
	}
}

func (s *quicProxyNATService) notify() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

type quicProxyNATPacket struct {
	buffer      *buf.Buffer
	destination M.Socksaddr
}

type quicProxyNATConn struct {
	service      *quicProxyNATService
	entry        *quicProxyNATEntry
	writer       N.PacketWriter
	packetChan   chan quicProxyNATPacket
	done         chan struct{}
	access       sync.Mutex
	writeAccess  sync.RWMutex
	closed       bool
	readDeadline pipe.Deadline
}

func (c *quicProxyNATConn) enqueue(payload []byte, destination M.Socksaddr) {
	buffer := buf.NewSize(len(payload))
	_, _ = buffer.Write(payload)
	c.access.Lock()
	defer c.access.Unlock()
	if c.closed {
		buffer.Release()
		return
	}
	select {
	case c.packetChan <- quicProxyNATPacket{buffer: buffer, destination: destination}:
	default:
		buffer.Release()
	}
}

func (c *quicProxyNATConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	select {
	case packet := <-c.packetChan:
		_, err := buffer.ReadOnceFrom(packet.buffer)
		packet.buffer.Release()
		return packet.destination, err
	case <-c.done:
		return M.Socksaddr{}, io.ErrClosedPipe
	case <-c.readDeadline.Wait():
		return M.Socksaddr{}, os.ErrDeadlineExceeded
	}
}

func (c *quicProxyNATConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	c.writeAccess.RLock()
	defer c.writeAccess.RUnlock()
	c.access.Lock()
	if c.closed {
		c.access.Unlock()
		buffer.Release()
		return net.ErrClosed
	}
	c.access.Unlock()
	return c.writer.WritePacket(buffer, destination)
}

func (c *quicProxyNATConn) Close() error {
	c.service.remove(c.entry)
	return nil
}

func (c *quicProxyNATConn) closeInternal() {
	c.writeAccess.Lock()
	defer c.writeAccess.Unlock()
	c.access.Lock()
	defer c.access.Unlock()
	if c.closed {
		return
	}
	c.closed = true
	close(c.done)
	for {
		select {
		case packet := <-c.packetChan:
			packet.buffer.Release()
		default:
			return
		}
	}
}

func (c *quicProxyNATConn) LocalAddr() net.Addr { return c.entry.source.UDPAddr() }
func (c *quicProxyNATConn) SetDeadline(time.Time) error {
	return os.ErrInvalid
}
func (c *quicProxyNATConn) SetReadDeadline(deadline time.Time) error {
	c.readDeadline.Set(deadline)
	return nil
}
func (c *quicProxyNATConn) SetWriteDeadline(time.Time) error { return os.ErrInvalid }

var _ N.PacketConn = (*quicProxyNATConn)(nil)
