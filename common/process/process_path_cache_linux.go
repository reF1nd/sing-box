//go:build linux

package process

import (
	"context"
	"fmt"
	"sync"
	"time"
)

const (
	processPathLifetime     = time.Second
	processPathMissLifetime = 200 * time.Millisecond
	processPathCapacity     = 64
	processPathMissCapacity = 256
)

type processPathSnapshot struct {
	paths   map[uint32]string
	expires time.Time
}

type processPathKey struct{ inode, uid uint32 }

type processPathScan struct {
	done     chan struct{}
	snapshot processPathSnapshot
	err      error
}

// Snapshots cache positive matches only. An inode absent from an old snapshot
// may be a newly created socket, so required lookups must refresh that scope.
// Negative entries refer only to an inode explicitly searched by a caller.
type processPathCache struct {
	access     sync.Mutex
	snapshots  map[uint32]processPathSnapshot
	misses     map[processPathKey]time.Time
	scans      map[uint32]*processPathScan
	ctx        context.Context
	cancel     context.CancelFunc
	generation uint64
	closed     bool
	now        func() time.Time
	build      func(context.Context, uint32) (map[uint32]string, error)
}

func newProcessPathCache(build func(context.Context, uint32) (map[uint32]string, error)) *processPathCache {
	c := &processPathCache{now: time.Now, build: build}
	c.reset()
	return c
}

func (c *processPathCache) reset() {
	c.access.Lock()
	defer c.access.Unlock()
	if c.closed {
		return
	}
	if c.cancel != nil {
		c.cancel()
	}
	c.ctx, c.cancel = context.WithCancel(context.Background())
	c.generation++
	c.snapshots = make(map[uint32]processPathSnapshot)
	c.misses = make(map[processPathKey]time.Time)
	c.scans = make(map[uint32]*processPathScan)
}

func (c *processPathCache) close() {
	c.access.Lock()
	defer c.access.Unlock()
	c.closed = true
	c.cancel()
	clear(c.snapshots)
	clear(c.misses)
}

func (c *processPathCache) cached(inode, uid uint32) string {
	c.access.Lock()
	defer c.access.Unlock()
	return c.cachedLocked(inode, uid)
}

func (c *processPathCache) cachedLocked(inode, uid uint32) string {
	for _, scope := range []uint32{uid, processPathsAllUsers} {
		if entry, ok := c.snapshots[scope]; ok && c.now().Before(entry.expires) {
			if paths := entry.paths[inode]; len(paths) > 0 {
				return paths
			}
		}
	}
	return ""
}

func (c *processPathCache) find(ctx context.Context, inode, uid uint32, required bool) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	c.access.Lock()
	if c.closed {
		c.access.Unlock()
		return "", context.Canceled
	}
	if paths := c.cachedLocked(inode, uid); len(paths) > 0 {
		c.access.Unlock()
		return paths, nil
	}
	key := processPathKey{inode, uid}
	if until, ok := c.misses[key]; ok && c.now().Before(until) {
		c.access.Unlock()
		return "", processPathNotFound(inode, uid)
	}
	generation := c.generation
	c.access.Unlock()
	complete := true
	// A socket UID can differ from the UID of its holder (netd, privilege
	// drops, descriptor passing). Preserve the all-process fallback.
	for _, scope := range []uint32{uid, processPathsAllUsers} {
		paths, scanned, err := c.scan(ctx, scope, inode, required, generation)
		if err != nil {
			return "", err
		}
		if len(paths) > 0 {
			return paths, nil
		}
		complete = complete && scanned
	}
	c.access.Lock()
	if complete && generation == c.generation && !c.closed {
		if len(c.misses) >= processPathMissCapacity {
			for key := range c.misses {
				delete(c.misses, key)
				break
			}
		}
		c.misses[key] = c.now().Add(processPathMissLifetime)
	}
	c.access.Unlock()
	return "", processPathNotFound(inode, uid)
}

func (c *processPathCache) scan(ctx context.Context, scope, inode uint32, required bool, generation uint64) (string, bool, error) {
	c.access.Lock()
	if c.closed || c.generation != generation {
		c.access.Unlock()
		return "", false, context.Canceled
	}
	if entry, ok := c.snapshots[scope]; ok && c.now().Before(entry.expires) {
		if paths := entry.paths[inode]; len(paths) > 0 {
			c.access.Unlock()
			return paths, true, nil
		}
		// Logging may reuse the snapshot, but a path rule must not interpret
		// this unsearched inode as an authoritative negative result.
		if !required {
			c.access.Unlock()
			return "", false, nil
		}
	}
	scan, ok := c.scans[scope]
	if !ok {
		scan = &processPathScan{done: make(chan struct{})}
		c.scans[scope] = scan
		go c.runScan(c.ctx, scope, generation, scan)
	}
	scanContext := c.ctx
	c.access.Unlock()
	select {
	case <-ctx.Done():
		return "", false, ctx.Err()
	case <-scanContext.Done():
		return "", false, scanContext.Err()
	case <-scan.done:
		if err := ctx.Err(); err != nil {
			return "", false, err
		}
		if err := scanContext.Err(); err != nil {
			return "", false, err
		}
		return scan.snapshot.paths[inode], true, scan.err
	}
}

func (c *processPathCache) runScan(ctx context.Context, scope uint32, generation uint64, scan *processPathScan) {
	paths, err := c.build(ctx, scope)
	c.access.Lock()
	defer c.access.Unlock()
	scan.snapshot = processPathSnapshot{paths, c.now().Add(processPathLifetime)}
	scan.err = err
	if !c.closed && generation == c.generation {
		delete(c.scans, scope)
		if err == nil {
			if len(c.snapshots) >= processPathCapacity {
				for key := range c.snapshots {
					delete(c.snapshots, key)
					break
				}
			}
			c.snapshots[scope] = scan.snapshot
		}
	}
	close(scan.done)
}

func processPathNotFound(inode, uid uint32) error {
	return fmt.Errorf("process of uid(%d), inode(%d): %w", uid, inode, ErrNotFound)
}
