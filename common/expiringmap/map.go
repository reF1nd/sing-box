package expiringmap

import (
	"container/heap"
	"sync"
	"time"
)

type entry[K comparable, V any] struct {
	key       K
	value     V
	expiresAt time.Time
	index     int
}

type entryHeap[K comparable, V any] []*entry[K, V]

func (h entryHeap[K, V]) Len() int { return len(h) }

func (h entryHeap[K, V]) Less(i, j int) bool {
	return h[i].expiresAt.Before(h[j].expiresAt)
}

func (h entryHeap[K, V]) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].index = i
	h[j].index = j
}

func (h *entryHeap[K, V]) Push(value any) {
	item := value.(*entry[K, V])
	item.index = len(*h)
	*h = append(*h, item)
}

func (h *entryHeap[K, V]) Pop() any {
	old := *h
	last := len(old) - 1
	item := old[last]
	old[last] = nil
	item.index = -1
	*h = old[:last]
	return item
}

// Map stores values for a fixed lifetime. Expiration is driven by one timer
// and a min-heap, so entries are removed without lookup-time polling, per-entry
// timers, capacity eviction, or periodic full-map scans.
type Map[K comparable, V any] struct {
	access   sync.Mutex
	entries  map[K]*entry[K, V]
	mapPeak  int
	queue    entryHeap[K, V]
	lifetime time.Duration
	wake     chan struct{}
	done     chan struct{}
	closed   bool
}

func New[K comparable, V any](lifetime time.Duration) *Map[K, V] {
	if lifetime <= 0 {
		panic("expiringmap: non-positive lifetime")
	}
	cache := &Map[K, V]{
		entries:  make(map[K]*entry[K, V]),
		lifetime: lifetime,
		wake:     make(chan struct{}, 1),
		done:     make(chan struct{}),
	}
	go cache.run()
	return cache
}

// Store inserts or refreshes a value. It returns false after the map is closed.
func (m *Map[K, V]) Store(key K, value V) bool {
	return m.storeIf(key, value, nil)
}

// StoreIf inserts or refreshes a value when allow accepts the current state. An
// expired current value is treated as absent. The allow callback runs while the
// map is locked, so it must not call back into the same map.
func (m *Map[K, V]) StoreIf(key K, value V, allow func(current V, loaded bool) bool) bool {
	return m.storeIf(key, value, allow)
}

func (m *Map[K, V]) storeIf(key K, value V, allow func(current V, loaded bool) bool) bool {
	now := time.Now()
	expiresAt := now.Add(m.lifetime)
	m.access.Lock()
	if m.closed {
		m.access.Unlock()
		return false
	}
	item, loaded := m.entries[key]
	if loaded && !item.expiresAt.After(now) {
		m.remove(item)
		item = nil
		loaded = false
	}
	if allow != nil {
		var current V
		if loaded {
			current = item.value
		}
		if !allow(current, loaded) {
			m.access.Unlock()
			return false
		}
	}
	if loaded {
		item.value = value
		item.expiresAt = expiresAt
		heap.Fix(&m.queue, item.index)
		m.access.Unlock()
		return true
	}
	wake := len(m.queue) == 0
	item = &entry[K, V]{key: key, value: value, expiresAt: expiresAt}
	m.entries[key] = item
	m.mapPeak = max(m.mapPeak, len(m.entries))
	heap.Push(&m.queue, item)
	m.access.Unlock()
	if wake {
		m.notify()
	}
	return true
}

func (m *Map[K, V]) Load(key K) (V, bool) {
	now := time.Now()
	m.access.Lock()
	defer m.access.Unlock()
	if m.closed {
		var zero V
		return zero, false
	}
	item, loaded := m.entries[key]
	if !loaded {
		var zero V
		return zero, false
	}
	if !item.expiresAt.After(now) {
		m.remove(item)
		var zero V
		return zero, false
	}
	return item.value, true
}

func (m *Map[K, V]) LoadAndRefresh(key K) (V, bool) {
	now := time.Now()
	expiresAt := now.Add(m.lifetime)
	m.access.Lock()
	defer m.access.Unlock()
	if m.closed {
		var zero V
		return zero, false
	}
	item, loaded := m.entries[key]
	if !loaded {
		var zero V
		return zero, false
	}
	if !item.expiresAt.After(now) {
		m.remove(item)
		var zero V
		return zero, false
	}
	item.expiresAt = expiresAt
	heap.Fix(&m.queue, item.index)
	return item.value, true
}

func (m *Map[K, V]) Len() int {
	m.access.Lock()
	defer m.access.Unlock()
	return len(m.entries)
}

func (m *Map[K, V]) Close() {
	m.access.Lock()
	if !m.closed {
		m.closed = true
		m.entries = nil
		m.mapPeak = 0
		m.queue = nil
	}
	m.access.Unlock()
	m.notify()
	<-m.done
}

func (m *Map[K, V]) run() {
	defer close(m.done)
	for {
		m.access.Lock()
		if m.closed {
			m.access.Unlock()
			return
		}
		m.removeExpired(time.Now())
		if len(m.queue) == 0 {
			m.access.Unlock()
			<-m.wake
			continue
		}
		wait := time.Until(m.queue[0].expiresAt)
		m.access.Unlock()
		if wait < 0 {
			wait = 0
		}
		timer := time.NewTimer(wait)
		select {
		case <-timer.C:
		case <-m.wake:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
		}
	}
}

func (m *Map[K, V]) removeExpired(now time.Time) {
	removed := false
	for len(m.queue) > 0 && !m.queue[0].expiresAt.After(now) {
		item := heap.Pop(&m.queue).(*entry[K, V])
		delete(m.entries, item.key)
		removed = true
	}
	if removed {
		m.compact()
	}
}

func (m *Map[K, V]) remove(item *entry[K, V]) {
	heap.Remove(&m.queue, item.index)
	delete(m.entries, item.key)
	m.compact()
}

func (m *Map[K, V]) compact() {
	remaining := len(m.entries)
	if remaining == 0 {
		m.entries = make(map[K]*entry[K, V])
		m.mapPeak = 0
		return
	}
	// Go maps do not shrink after deletion. Rebuild only after a substantial
	// contraction, keeping the occasional O(N) copy amortized.
	if m.mapPeak < 1024 || remaining > m.mapPeak/4 {
		return
	}
	compacted := make(map[K]*entry[K, V], remaining)
	for key, item := range m.entries {
		compacted[key] = item
	}
	m.entries = compacted
	m.mapPeak = remaining
}

func (m *Map[K, V]) notify() {
	select {
	case m.wake <- struct{}{}:
	default:
	}
}
