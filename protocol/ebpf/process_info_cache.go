//go:build with_ebpf && (linux || android)

package ebpf

import (
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
)

// eBPF process tracking gives us a stable process identity for a socket. The
// identity is still resolved to user-visible metadata through procfs and the
// platform package manager, though. Cache that relatively expensive lookup
// briefly: a process commonly opens many sockets in a short burst, while the
// short lifetime limits stale data if the kernel reuses a PID.
const (
	processInfoCacheCapacity         = 256
	processInfoCacheLifetime         = time.Second
	processInfoNegativeCacheLifetime = 200 * time.Millisecond
)

type processInfoCacheKey struct {
	processID uint32
	userID    uint32
}

type processInfoCacheEntry struct {
	info      *adapter.ConnectionOwner
	err       error
	expiresAt time.Time
}

type processInfoLookup struct {
	done    chan struct{}
	waiters int
}

type processInfoCache struct {
	access   sync.Mutex
	entries  map[processInfoCacheKey]processInfoCacheEntry
	inFlight map[processInfoCacheKey]*processInfoLookup
}

func newProcessInfoCache() *processInfoCache {
	return &processInfoCache{
		entries:  make(map[processInfoCacheKey]processInfoCacheEntry),
		inFlight: make(map[processInfoCacheKey]*processInfoLookup),
	}
}

func (c *processInfoCache) load(key processInfoCacheKey, now time.Time) (*adapter.ConnectionOwner, error, bool) {
	if c == nil {
		return nil, nil, false
	}
	c.access.Lock()
	defer c.access.Unlock()
	return c.loadLocked(key, now)
}

func (c *processInfoCache) loadLocked(key processInfoCacheKey, now time.Time) (*adapter.ConnectionOwner, error, bool) {
	entry, loaded := c.entries[key]
	if !loaded {
		return nil, nil, false
	}
	if !now.Before(entry.expiresAt) {
		delete(c.entries, key)
		return nil, nil, false
	}
	return entry.info, entry.err, true
}

func (c *processInfoCache) store(key processInfoCacheKey, info *adapter.ConnectionOwner, err error, now time.Time) {
	if c == nil {
		return
	}
	c.access.Lock()
	defer c.access.Unlock()
	c.storeLocked(key, info, err, now)
}

func (c *processInfoCache) storeLocked(key processInfoCacheKey, info *adapter.ConnectionOwner, err error, now time.Time) {
	for cachedKey, entry := range c.entries {
		if !now.Before(entry.expiresAt) {
			delete(c.entries, cachedKey)
		}
	}
	if _, loaded := c.entries[key]; !loaded && len(c.entries) >= processInfoCacheCapacity {
		// Entries are deliberately short-lived. If the cache is full before an
		// expiry pass can reclaim one, evict an arbitrary entry rather than
		// allowing process churn to grow memory without bound.
		for cachedKey := range c.entries {
			delete(c.entries, cachedKey)
			break
		}
	}
	lifetime := processInfoCacheLifetime
	if err != nil {
		lifetime = processInfoNegativeCacheLifetime
	}
	c.entries[key] = processInfoCacheEntry{info: info, err: err, expiresAt: now.Add(lifetime)}
}

// loadOrResolve combines concurrent misses for one process. The bool result is
// true only for the caller that performed resolve, allowing it to report an
// error once while cache hits and joined callers stay quiet.
func (c *processInfoCache) loadOrResolve(
	key processInfoCacheKey,
	resolve func() (*adapter.ConnectionOwner, error),
) (*adapter.ConnectionOwner, error, bool) {
	if c == nil {
		info, err := resolve()
		return info, err, true
	}
	for {
		now := time.Now()
		c.access.Lock()
		if info, err, loaded := c.loadLocked(key, now); loaded {
			c.access.Unlock()
			return info, err, false
		}
		if lookup, loaded := c.inFlight[key]; loaded {
			lookup.waiters++
			done := lookup.done
			c.access.Unlock()
			<-done
			continue
		}
		lookup := &processInfoLookup{done: make(chan struct{})}
		c.inFlight[key] = lookup
		c.access.Unlock()

		info, err := resolve()
		c.access.Lock()
		c.storeLocked(key, info, err, time.Now())
		delete(c.inFlight, key)
		close(lookup.done)
		c.access.Unlock()
		return info, err, true
	}
}
