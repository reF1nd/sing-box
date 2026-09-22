//go:build with_ebpf && (linux || android)

package ebpf

import (
	"container/heap"
	"sync"
	"time"
)

type udpNATCleanupEntry struct {
	conn     *udpNATConn
	deadline time.Time
	index    int
}

type udpNATCleanupQueue struct {
	service *udpNATService
	access  sync.Mutex
	wake    chan struct{}
	entries udpNATCleanupHeap
}

func newUDPNATCleanupQueue(service *udpNATService) *udpNATCleanupQueue {
	return &udpNATCleanupQueue{
		service: service,
		wake:    make(chan struct{}, 1),
	}
}

func (q *udpNATCleanupQueue) notify() {
	select {
	case q.wake <- struct{}{}:
	default:
	}
}

func (q *udpNATCleanupQueue) addOrUpdate(entry *udpNATCleanupEntry, deadline time.Time) {
	if entry == nil || q.service.closed.Load() {
		return
	}
	q.access.Lock()
	if entry.conn.isClosed() && deadline.After(time.Now()) {
		deadline = time.Now()
	}
	entry.deadline = deadline
	if entry.index == -1 {
		heap.Push(&q.entries, entry)
	} else {
		heap.Fix(&q.entries, entry.index)
	}
	q.access.Unlock()
	q.notify()
}

func (q *udpNATCleanupQueue) remove(entry *udpNATCleanupEntry) {
	if entry == nil {
		return
	}
	q.access.Lock()
	if entry.index != -1 {
		heap.Remove(&q.entries, entry.index)
	}
	q.access.Unlock()
	q.notify()
}

func (q *udpNATCleanupQueue) next() (time.Time, bool) {
	q.access.Lock()
	defer q.access.Unlock()
	if len(q.entries) == 0 {
		return time.Time{}, false
	}
	return q.entries[0].deadline, true
}

func (q *udpNATCleanupQueue) popDue(now time.Time) *udpNATCleanupEntry {
	q.access.Lock()
	defer q.access.Unlock()
	if len(q.entries) == 0 || q.entries[0].deadline.After(now) {
		return nil
	}
	return heap.Pop(&q.entries).(*udpNATCleanupEntry)
}

func (q *udpNATCleanupQueue) clear() {
	q.access.Lock()
	for _, entry := range q.entries {
		entry.index = -1
	}
	clear(q.entries)
	q.entries = nil
	q.access.Unlock()
	q.notify()
}

type udpNATCleanupHeap []*udpNATCleanupEntry

func (h udpNATCleanupHeap) Len() int { return len(h) }

func (h udpNATCleanupHeap) Less(left int, right int) bool {
	return h[left].deadline.Before(h[right].deadline)
}

func (h udpNATCleanupHeap) Swap(left int, right int) {
	h[left], h[right] = h[right], h[left]
	h[left].index = left
	h[right].index = right
}

func (h *udpNATCleanupHeap) Push(value any) {
	entry := value.(*udpNATCleanupEntry)
	entry.index = len(*h)
	*h = append(*h, entry)
}

func (h *udpNATCleanupHeap) Pop() any {
	items := *h
	last := len(items) - 1
	entry := items[last]
	items[last] = nil
	entry.index = -1
	*h = items[:last]
	return entry
}

func (s *udpNATService) cleanupLoop() {
	defer s.cleanupWait.Done()
	timer := time.NewTimer(time.Hour)
	stopUDPNATCleanupTimer(timer)
	defer timer.Stop()
	for {
		select {
		case <-s.cleanup.wake:
		default:
		}
		deadline, loaded := s.cleanup.next()
		if !loaded {
			select {
			case <-s.cleanupDone:
				return
			case <-s.cleanup.wake:
				continue
			}
		}
		if delay := time.Until(deadline); delay > 0 {
			timer.Reset(delay)
			select {
			case <-s.cleanupDone:
				stopUDPNATCleanupTimer(timer)
				return
			case <-s.cleanup.wake:
				stopUDPNATCleanupTimer(timer)
				continue
			case <-timer.C:
			}
		}
		for {
			entry := s.cleanup.popDue(time.Now())
			if entry == nil {
				break
			}
			s.cleanupEntry(entry)
		}
	}
}

func (s *udpNATService) cleanupEntry(entry *udpNATCleanupEntry) {
	conn, lifetime, loaded := s.cache.PeekWithLifetime(entry.conn.key)
	if !loaded || conn != entry.conn || lifetime.IsZero() {
		return
	}
	if conn.isClosed() {
		s.cache.Remove(entry.conn.key)
		return
	}
	s.cleanup.addOrUpdate(entry, lifetime)
}

func stopUDPNATCleanupTimer(timer *time.Timer) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
}
