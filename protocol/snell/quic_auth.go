package snell

import (
	"net/netip"
	"sync"

	snellprotocol "github.com/sagernet/sing-snell"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
)

const (
	quicProxyAuthenticationWorkers   = 4
	quicProxyAuthenticationQueueSize = 1024
	quicProxyPendingPacketLimit      = 8
	quicProxyPendingBytesLimit       = 64 * 1024
)

type quicProxyAuthenticationTask struct {
	source       M.Socksaddr
	init         []byte
	packets      [][]byte
	pendingBytes int
}

type quicProxyAuthenticationService struct {
	parser quicProxyInitParser
	nat    *quicProxyNATService
	logger logger.ContextLogger

	access  sync.Mutex
	pending map[netip.AddrPort]*quicProxyAuthenticationTask
	queue   chan *quicProxyAuthenticationTask
	done    chan struct{}
	closed  bool
	workers sync.WaitGroup
}

func newQUICProxyAuthenticationService(parser quicProxyInitParser, nat *quicProxyNATService, logger logger.ContextLogger) *quicProxyAuthenticationService {
	service := &quicProxyAuthenticationService{
		parser:  parser,
		nat:     nat,
		logger:  logger,
		pending: make(map[netip.AddrPort]*quicProxyAuthenticationTask),
		queue:   make(chan *quicProxyAuthenticationTask, quicProxyAuthenticationQueueSize),
		done:    make(chan struct{}),
	}
	service.workers.Add(quicProxyAuthenticationWorkers)
	for range quicProxyAuthenticationWorkers {
		go service.run()
	}
	return service
}

func (s *quicProxyAuthenticationService) Submit(source M.Socksaddr, data []byte) bool {
	key := source.AddrPort()
	s.access.Lock()
	defer s.access.Unlock()
	if s.closed {
		return false
	}
	if task, loaded := s.pending[key]; loaded {
		s.appendPendingPacket(task, data)
		return true
	}
	if len(s.queue) >= cap(s.queue) {
		return false
	}
	task := &quicProxyAuthenticationTask{
		source: source,
		init:   append([]byte(nil), data...),
	}
	select {
	case s.queue <- task:
		s.pending[key] = task
		return true
	default:
		return false
	}
}

func (s *quicProxyAuthenticationService) QueuePending(source M.Socksaddr, data []byte) bool {
	key := source.AddrPort()
	s.access.Lock()
	defer s.access.Unlock()
	if s.closed {
		return false
	}
	task, loaded := s.pending[key]
	if !loaded {
		return false
	}
	s.appendPendingPacket(task, data)
	return true
}

func (s *quicProxyAuthenticationService) appendPendingPacket(task *quicProxyAuthenticationTask, data []byte) {
	if len(task.packets) >= quicProxyPendingPacketLimit || task.pendingBytes+len(data) > quicProxyPendingBytesLimit {
		return
	}
	task.packets = append(task.packets, append([]byte(nil), data...))
	task.pendingBytes += len(data)
}

func (s *quicProxyAuthenticationService) run() {
	defer s.workers.Done()
	for {
		select {
		case <-s.done:
			return
		default:
		}
		select {
		case <-s.done:
			return
		case task := <-s.queue:
			s.authenticate(task)
		}
	}
}

func (s *quicProxyAuthenticationService) authenticate(task *quicProxyAuthenticationTask) {
	session, payload, err := s.parser.ParseQUICProxyInit(task.init)
	key := task.source.AddrPort()
	s.access.Lock()
	if s.pending[key] != task {
		s.access.Unlock()
		return
	}
	if s.closed {
		delete(s.pending, key)
		s.access.Unlock()
		return
	}
	if err != nil {
		delete(s.pending, key)
		s.access.Unlock()
		s.logger.Debug("quic proxy: reject init from ", task.source, ": ", err)
		return
	}
	created := s.nat.NewSession(task.source, session, payload)
	delete(s.pending, key)
	packets := task.packets
	s.access.Unlock()
	if !created {
		s.logger.Debug("quic proxy: session already exists for ", task.source)
		return
	}
	s.logger.Info("quic proxy: new session from ", task.source, " to ", session.Target())
	for _, packet := range packets {
		entry, loaded := s.nat.Session(task.source)
		if !loaded {
			return
		}
		packetPayload := packet
		if !snellprotocol.IsQUICLooking(packet[0]) {
			packetPayload, err = entry.session.DecodeDuplicateInit(packet)
			if err != nil {
				s.logger.Debug("quic proxy: reject pending duplicate init from ", task.source, ": ", err)
				continue
			}
		}
		s.nat.NewPacket(entry, packetPayload)
	}
}

func (s *quicProxyAuthenticationService) Close() {
	s.access.Lock()
	if s.closed {
		s.access.Unlock()
		s.workers.Wait()
		s.drainQueue()
		return
	}
	s.closed = true
	clear(s.pending)
	close(s.done)
	s.access.Unlock()
	s.workers.Wait()
	s.drainQueue()
}

func (s *quicProxyAuthenticationService) drainQueue() {
	for {
		select {
		case <-s.queue:
		default:
			return
		}
	}
}
