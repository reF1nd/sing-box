//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing/common/bufio"
	N "github.com/sagernet/sing/common/network"
)

const (
	// One transparent reply socket exists per distinct original destination
	// reached through a non-cgroup data plane. Bound the whole pool rather than
	// each shard so hash distribution cannot reject work below this limit.
	udpReplySocketCapacity = 4096

	// Idle sockets are reclaimed at their next actual expiry deadline in
	// addition to capacity-triggered eviction in get().
	udpReplySocketIdleTimeout = 5 * time.Minute
)

var errUDPReplySocketCapacity = errors.New("UDP eBPF reply socket pool is at capacity")

// udpReplySocketPool shares transparent reply sockets between all clients of
// an inbound. A socket bound to an original destination can send replies to any
// client, so keeping it at client-state scope needlessly multiplies sockets.
//
// The pool is globally capacity-bounded and idle sockets are reclaimed by a
// background sweeper as well as opportunistically when the pool is full and a
// new destination needs a socket. get() marks the entry it returns as in use
// until the caller invokes the release func it also returns; eviction skips
// any entry still in use, so a send in flight is never handed a closed
// connection by a reclaim racing it from another goroutine. Full-pool
// close()/reset() are unconditional instead: those are deliberate,
// whole-pool lifecycle events (inbound shutdown, network change) the caller
// already treats a resulting write error as expected, not an eviction a send
// could be caught unaware by.
type udpReplySocketPool struct {
	shards       [udpClientShardCount]udpReplySocketShard
	createAccess sync.Mutex
	closed       atomic.Bool
	stats        udpReplySocketPoolStats
	sweepAccess  sync.Mutex
	sweepCancel  context.CancelFunc
	sweepWake    chan struct{}
	sweepDone    chan struct{}
	capacity     int64         // test override; zero uses udpReplySocketCapacity
	idleTimeout  time.Duration // test override; zero uses udpReplySocketIdleTimeout
}

type udpReplySocketShard struct {
	access  sync.Mutex
	sockets map[netip.AddrPort]*udpReplySocketEntry
}

type udpReplySocketEntry struct {
	conn     *net.UDPConn
	writer   N.PacketBatchWriter
	cleanup  func()
	lastUsed atomic.Int64 // UnixNano, updated on every get()
	inUse    atomic.Int32 // active senders; eviction skips entries > 0
}

// udpReplySocketPoolStats exposes current usage, its high-water mark, and how
// often capacity handling reclaimed or refused a socket.
type udpReplySocketPoolStats struct {
	count            atomic.Int64
	peak             atomic.Int64
	evicted          atomic.Int64
	capacityRejected atomic.Int64
}

// udpReplySocketPoolSnapshot is a point-in-time, non-atomic-together read of
// udpReplySocketPoolStats for diagnostics/logging.
type udpReplySocketPoolSnapshot struct {
	Count            int64 `json:"count"`
	Peak             int64 `json:"peak"`
	Evicted          int64 `json:"evicted"`
	CapacityRejected int64 `json:"capacity_rejected"`
}

func (p *udpReplySocketPool) snapshot() udpReplySocketPoolSnapshot {
	return udpReplySocketPoolSnapshot{
		Count:            p.stats.count.Load(),
		Peak:             p.stats.peak.Load(),
		Evicted:          p.stats.evicted.Load(),
		CapacityRejected: p.stats.capacityRejected.Load(),
	}
}

func (p *udpReplySocketPool) get(
	source netip.AddrPort,
	create func(netip.AddrPort) (*net.UDPConn, func(), error),
) (*udpReplySocketEntry, func(), error) {
	if p.closed.Load() {
		return nil, nil, net.ErrClosed
	}
	shard := &p.shards[p.shardIndex(source)]
	shard.access.Lock()
	if p.closed.Load() {
		shard.access.Unlock()
		return nil, nil, net.ErrClosed
	}
	if entry := shard.sockets[source]; entry != nil {
		entry.lastUsed.Store(time.Now().UnixNano())
		entry.inUse.Add(1)
		shard.access.Unlock()
		return entry, releaseUDPReplySocketEntry(entry), nil
	}
	shard.access.Unlock()

	// Cache misses create kernel sockets and are already the slow path. Serialize
	// only this path so the global count check and admission remain exact while
	// cache hits continue to use their shard lock alone.
	p.createAccess.Lock()
	defer p.createAccess.Unlock()
	if p.closed.Load() {
		return nil, nil, net.ErrClosed
	}
	shard.access.Lock()
	if entry := shard.sockets[source]; entry != nil {
		entry.lastUsed.Store(time.Now().UnixNano())
		entry.inUse.Add(1)
		shard.access.Unlock()
		return entry, releaseUDPReplySocketEntry(entry), nil
	}
	shard.access.Unlock()
	if p.stats.count.Load() >= p.socketCapacity() && !p.evictOldestIdle() {
		p.stats.capacityRejected.Add(1)
		return nil, nil, errUDPReplySocketCapacity
	}
	socket, cleanup, err := create(source)
	if err != nil {
		return nil, nil, err
	}
	entry := &udpReplySocketEntry{
		conn:    socket,
		writer:  bufio.NewPacketBatchWriter(bufio.NewPacketConn(socket)),
		cleanup: cleanup,
	}
	entry.lastUsed.Store(time.Now().UnixNano())
	entry.inUse.Store(1)
	if p.closed.Load() {
		if cleanup != nil {
			cleanup()
		}
		_ = socket.Close()
		return nil, nil, net.ErrClosed
	}
	shard.access.Lock()
	if shard.sockets == nil {
		shard.sockets = make(map[netip.AddrPort]*udpReplySocketEntry)
	}
	shard.sockets[source] = entry
	shard.access.Unlock()
	p.addCount(1)
	p.requestSweep()
	return entry, releaseUDPReplySocketEntry(entry), nil
}

func (p *udpReplySocketPool) socketCapacity() int64 {
	if p.capacity > 0 {
		return p.capacity
	}
	return udpReplySocketCapacity
}

func releaseUDPReplySocketEntry(entry *udpReplySocketEntry) func() {
	return func() { entry.inUse.Add(-1) }
}

func (p *udpReplySocketPool) addCount(delta int64) {
	updated := p.stats.count.Add(delta)
	for {
		peak := p.stats.peak.Load()
		if updated <= peak || p.stats.peak.CompareAndSwap(peak, updated) {
			return
		}
	}
}

// evictOldestIdle makes room at the global limit. It never holds more than one
// shard lock and validates the selected entry before closing it, so concurrent
// cache hits cannot lose a socket that became active during the scan.
func (p *udpReplySocketPool) evictOldestIdle() bool {
	for attempt := 0; attempt < 2; attempt++ {
		selectedShard := -1
		var selectedSource netip.AddrPort
		var selectedEntry *udpReplySocketEntry
		var selectedLastUsed int64
		for index := range p.shards {
			shard := &p.shards[index]
			shard.access.Lock()
			for source, entry := range shard.sockets {
				lastUsed := entry.lastUsed.Load()
				if entry.inUse.Load() == 0 && (selectedEntry == nil || lastUsed < selectedLastUsed) {
					selectedShard = index
					selectedSource = source
					selectedEntry = entry
					selectedLastUsed = lastUsed
				}
			}
			shard.access.Unlock()
		}
		if selectedEntry == nil {
			return false
		}
		shard := &p.shards[selectedShard]
		shard.access.Lock()
		if shard.sockets[selectedSource] != selectedEntry || selectedEntry.inUse.Load() != 0 || selectedEntry.lastUsed.Load() != selectedLastUsed {
			shard.access.Unlock()
			continue
		}
		if selectedEntry.cleanup != nil {
			selectedEntry.cleanup()
		}
		_ = selectedEntry.conn.Close()
		delete(shard.sockets, selectedSource)
		shard.access.Unlock()
		p.stats.count.Add(-1)
		p.stats.evicted.Add(1)
		return true
	}
	return false
}

func (p *udpReplySocketPool) shardIndex(source netip.AddrPort) int {
	return shardIndexForAddrPort(source, udpClientShardCount)
}

// startSweeper starts deadline-driven idle-socket reclaim. A second call before
// stopSweeper is a no-op.
func (p *udpReplySocketPool) startSweeper(ctx context.Context) {
	p.sweepAccess.Lock()
	if p.sweepCancel != nil {
		p.sweepAccess.Unlock()
		return
	}
	sweepCtx, cancel := context.WithCancel(ctx)
	wake := make(chan struct{}, 1)
	done := make(chan struct{})
	p.sweepCancel = cancel
	p.sweepWake = wake
	p.sweepDone = done
	p.sweepAccess.Unlock()
	go p.runSweeper(sweepCtx, wake, done)
	p.requestSweep()
}

// stopSweeper stops the background idle-socket reclaim. Safe to call even if
// startSweeper was never called, and safe to call more than once.
func (p *udpReplySocketPool) stopSweeper() {
	p.sweepAccess.Lock()
	cancel := p.sweepCancel
	done := p.sweepDone
	p.sweepCancel = nil
	p.sweepWake = nil
	p.sweepDone = nil
	p.sweepAccess.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
}

func (p *udpReplySocketPool) requestSweep() {
	p.sweepAccess.Lock()
	wake := p.sweepWake
	p.sweepAccess.Unlock()
	if wake == nil {
		return
	}
	select {
	case wake <- struct{}{}:
	default:
	}
}

func (p *udpReplySocketPool) runSweeper(ctx context.Context, wake <-chan struct{}, done chan<- struct{}) {
	defer close(done)
	timer := time.NewTimer(time.Hour)
	if !timer.Stop() {
		<-timer.C
	}
	defer timer.Stop()
	var timerChannel <-chan time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-wake:
		case <-timerChannel:
		}
		next, available := p.sweepIdleAt(time.Now(), p.socketIdleTimeout())
		if !available {
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timerChannel = nil
			continue
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		delay := time.Until(next)
		if delay < 0 {
			delay = 0
		}
		timer.Reset(delay)
		timerChannel = timer.C
	}
}

func (p *udpReplySocketPool) socketIdleTimeout() time.Duration {
	if p.idleTimeout > 0 {
		return p.idleTimeout
	}
	return udpReplySocketIdleTimeout
}

// sweepIdle closes every socket that has been idle (unused, and not
// currently in use by an in-flight send) for at least idleTimeout, so a
// destination that stops being contacted does not simply hold its socket
// until the shard happens to fill up.
func (p *udpReplySocketPool) sweepIdle(idleTimeout time.Duration) {
	p.sweepIdleAt(time.Now(), idleTimeout)
}

func (p *udpReplySocketPool) sweepIdleAt(now time.Time, idleTimeout time.Duration) (time.Time, bool) {
	if p.closed.Load() {
		return time.Time{}, false
	}
	deadline := now.Add(-idleTimeout).UnixNano()
	var next time.Time
	for index := range p.shards {
		shard := &p.shards[index]
		shard.access.Lock()
		for source, entry := range shard.sockets {
			lastUsed := entry.lastUsed.Load()
			expires := time.Unix(0, lastUsed).Add(idleTimeout)
			if entry.inUse.Load() > 0 {
				if !expires.After(now) {
					expires = now.Add(idleTimeout)
				}
				if next.IsZero() || expires.Before(next) {
					next = expires
				}
				continue
			}
			if lastUsed > deadline {
				if next.IsZero() || expires.Before(next) {
					next = expires
				}
				continue
			}
			if entry.cleanup != nil {
				entry.cleanup()
			}
			_ = entry.conn.Close()
			delete(shard.sockets, source)
			p.stats.count.Add(-1)
			p.stats.evicted.Add(1)
		}
		shard.access.Unlock()
	}
	return next, !next.IsZero()
}

func (p *udpReplySocketPool) close() error {
	if !p.closed.CompareAndSwap(false, true) {
		return nil
	}
	return p.closeSockets()
}

// reset closes sockets tied to the previous network path while keeping the
// pool usable for the next interface generation.
func (p *udpReplySocketPool) reset() error {
	if p == nil || p.closed.Load() {
		return nil
	}
	return p.closeSockets()
}

func (p *udpReplySocketPool) closeSockets() error {
	p.createAccess.Lock()
	defer p.createAccess.Unlock()
	var closeErr error
	for index := range p.shards {
		shard := &p.shards[index]
		shard.access.Lock()
		for source, entry := range shard.sockets {
			if entry.cleanup != nil {
				entry.cleanup()
			}
			closeErr = errors.Join(closeErr, entry.conn.Close())
			delete(shard.sockets, source)
			p.stats.count.Add(-1)
		}
		shard.access.Unlock()
	}
	p.requestSweep()
	return closeErr
}
