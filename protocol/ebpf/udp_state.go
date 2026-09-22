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

	commonEBPF "github.com/CHIZI-0618/sing-ebpf"
	"github.com/sagernet/sing/common/bufio"
	N "github.com/sagernet/sing/common/network"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	udpClientShardCount = 16
	udpReplyAliasLimit  = 64

	// One transparent reply socket exists per distinct original destination
	// reached through a non-cgroup data plane. Bound the whole pool rather than
	// each shard so hash distribution cannot reject work below this limit.
	udpReplySocketCapacity = 4096

	// Idle sockets are reclaimed at their next actual expiry deadline in
	// addition to capacity-triggered eviction in get().
	udpReplySocketIdleTimeout = 5 * time.Minute
)

var errUDPReplySocketCapacity = errors.New("UDP eBPF reply socket pool is at capacity")

type udpClientTable struct {
	clientShards     [udpClientShardCount]udpClientShard
	redirectAccess   sync.RWMutex
	redirectSessions map[udpRedirectSessionKey]udpSessionKey
}

type udpClientShard struct {
	access  sync.RWMutex
	clients map[udpSessionKey]*udpClientState
}

type udpRedirectSessionKey struct {
	client  netip.AddrPort
	address netip.Addr
}

type udpSessionScope uint8

const (
	udpSessionScopeLocalCgroup udpSessionScope = iota + 1
	udpSessionScopeLocalTC
	udpSessionScopeSharedTC
	udpSessionScopeSharedRewrite
)

// udpSessionKey keeps kernel identities which are stronger than the source
// address in the userspace association key. Source alone is ambiguous for
// SO_REUSEPORT sockets and when the same downstream address appears on more
// than one ingress interface.
type udpSessionKey struct {
	Source         netip.AddrPort
	Scope          udpSessionScope
	SocketCookie   uint64
	InterfaceIndex uint32
}

type udpNATContextKey struct{}

func udpSessionKeyFromContext(ctx context.Context) (udpSessionKey, bool) {
	key, loaded := ctx.Value(udpNATContextKey{}).(udpSessionKey)
	return key, loaded
}

type udpClientState struct {
	access          sync.RWMutex
	sourceMAC       net.HardwareAddr
	socketCookie    uint64
	bindings        map[netip.AddrPort]udpRedirectBinding
	replyAliasCount uint16
	closed          bool
	cgroupDataPlane bool
	cgroupOriginals map[netip.Addr]commonEBPF.OriginalDestination
}

type udpRedirectBinding struct {
	replyAlias      bool
	redirectAddress netip.Addr
	packetInfo      []byte
	connected       bool
}

func (t *udpClientTable) load(key udpSessionKey) (*udpClientState, bool) {
	shard := t.clientShard(key)
	shard.access.RLock()
	state, loaded := shard.clients[key]
	shard.access.RUnlock()
	return state, loaded
}

func (t *udpClientTable) loadOrCreate(key udpSessionKey) *udpClientState {
	if state, loaded := t.load(key); loaded {
		return state
	}
	shard := t.clientShard(key)
	shard.access.Lock()
	defer shard.access.Unlock()
	if state, loaded := shard.clients[key]; loaded {
		return state
	}
	if shard.clients == nil {
		shard.clients = make(map[udpSessionKey]*udpClientState)
	}
	state := &udpClientState{
		bindings:        make(map[netip.AddrPort]udpRedirectBinding),
		cgroupOriginals: make(map[netip.Addr]commonEBPF.OriginalDestination),
	}
	shard.clients[key] = state
	return state
}

func (t *udpClientTable) cachedCgroupOriginal(client netip.AddrPort, redirectAddress netip.Addr) (udpSessionKey, commonEBPF.OriginalDestination, bool) {
	lookupKey := udpRedirectSessionKey{client: client, address: redirectAddress}
	t.redirectAccess.RLock()
	key, loaded := t.redirectSessions[lookupKey]
	t.redirectAccess.RUnlock()
	if !loaded {
		return udpSessionKey{}, commonEBPF.OriginalDestination{}, false
	}
	state, loaded := t.load(key)
	if !loaded {
		return udpSessionKey{}, commonEBPF.OriginalDestination{}, false
	}
	state.access.RLock()
	original, loaded := state.cgroupOriginals[redirectAddress]
	state.access.RUnlock()
	return key, original, loaded
}

func (t *udpClientTable) setCgroupBinding(key udpSessionKey, original commonEBPF.OriginalDestination, redirectAddress netip.Addr) {
	state := t.loadOrCreate(key)
	state.access.Lock()
	state.cgroupOriginals[redirectAddress] = original
	state.socketCookie = original.SocketCookie
	state.cgroupDataPlane = true
	state.bindings[original.Destination] = udpRedirectBinding{
		redirectAddress: redirectAddress,
		packetInfo:      sourcePacketInfo(redirectAddress),
		connected:       original.ConnectedUDP,
	}
	state.access.Unlock()
	t.redirectAccess.Lock()
	if t.redirectSessions == nil {
		t.redirectSessions = make(map[udpRedirectSessionKey]udpSessionKey)
	}
	t.redirectSessions[udpRedirectSessionKey{client: key.Source, address: redirectAddress}] = key
	t.redirectAccess.Unlock()
}

func (t *udpClientTable) setCgroupReplyBinding(key udpSessionKey, expected *udpClientState, destination netip.AddrPort, redirectAddress netip.Addr) bool {
	shard := t.clientShard(key)
	shard.access.RLock()
	defer shard.access.RUnlock()
	if shard.clients[key] != expected {
		return false
	}
	expected.access.Lock()
	defer expected.access.Unlock()
	if expected.closed || expected.replyAliasCount >= udpReplyAliasLimit {
		return false
	}
	expected.cgroupOriginals[redirectAddress] = commonEBPF.OriginalDestination{Destination: destination}
	expected.cgroupDataPlane = true
	expected.bindings[destination] = udpRedirectBinding{
		replyAlias:      true,
		redirectAddress: redirectAddress,
		packetInfo:      sourcePacketInfo(redirectAddress),
	}
	expected.replyAliasCount++
	t.redirectAccess.Lock()
	if t.redirectSessions == nil {
		t.redirectSessions = make(map[udpRedirectSessionKey]udpSessionKey)
	}
	t.redirectSessions[udpRedirectSessionKey{client: key.Source, address: redirectAddress}] = key
	t.redirectAccess.Unlock()
	return true
}

func (t *udpClientTable) clientShard(key udpSessionKey) *udpClientShard {
	return &t.clientShards[shardIndexForAddrPort(key.Source, udpClientShardCount)]
}

// shardIndexForAddrPort distributes addr:port pairs across shardCount (a
// power of two) shards by hashing every address byte together with the
// port, not the port alone. A port-only key collapses onto a single shard
// whenever many distinct addresses happen to share one port -- exactly the
// common case for both callers of this function: UDP destinations
// overwhelmingly cluster on a handful of well-known ports (443, 53, ...)
// while varying in address, and independent client hosts can coincidentally
// reuse the same ephemeral source port for unrelated connections.
//
// This is a statistical improvement over the port-only key for realistic,
// naturally-varying traffic (see the package's shard-distribution tests),
// not a guarantee of even placement for every possible input set: FNV-1a is
// not a cryptographic hash, so a party able to choose destination addresses
// specifically to collide under it could still concentrate them onto one
// shard. This function only changes how inputs are distributed across
// shards; it does not change what happens once a shard fills. Of this
// function's two callers, only udpReplySocketPool enforces a per-shard
// capacity at all (udpReplySocketShardCapacity, with capacity-triggered
// eviction and rejection in get()) -- the client tables
// (udpClientTable/sharedUDPClientTable) have no capacity bound on a shard's
// map and grow with however many sessions are actually active. For the
// reply socket pool specifically: its usable total capacity before any
// single destination pattern hits a capacity rejection on its own shard
// still depends on how evenly that traffic happens to hash, not simply on
// udpClientShardCount * udpReplySocketShardCapacity -- that product is the
// pool's absolute ceiling under perfectly even placement, not a promised
// floor for every traffic shape.
func shardIndexForAddrPort(addrPort netip.AddrPort, shardCount int) int {
	const offset64 = 14695981039346656037
	const prime64 = 1099511628211
	hash := uint64(offset64)
	for _, b := range addrPort.Addr().As16() {
		hash ^= uint64(b)
		hash *= prime64
	}
	port := addrPort.Port()
	hash ^= uint64(port)
	hash *= prime64
	hash ^= uint64(port >> 8)
	hash *= prime64
	return int(hash & uint64(shardCount-1))
}

// count reports the number of tracked UDP clients, for diagnostics. It locks
// each shard in turn rather than all at once, so this is a point-in-time
// estimate under concurrent traffic, not a value consistent with any single
// instant -- adequate for a diagnostics counter, not for anything that would
// act on the exact number.
func (t *udpClientTable) count() int {
	total := 0
	for index := range t.clientShards {
		shard := &t.clientShards[index]
		shard.access.RLock()
		total += len(shard.clients)
		shard.access.RUnlock()
	}
	return total
}

func (t *udpClientTable) setDirectBinding(
	key udpSessionKey,
	destination netip.AddrPort,
	sourceMAC net.HardwareAddr,
	socketCookie uint64,
) {
	state := t.loadOrCreate(key)
	state.access.Lock()
	defer state.access.Unlock()
	if len(sourceMAC) > 0 {
		state.sourceMAC = append(state.sourceMAC[:0], sourceMAC...)
	}
	state.socketCookie = socketCookie
	state.bindings[destination] = udpRedirectBinding{}
}

func (t *udpClientTable) setDirectReplyBinding(
	key udpSessionKey,
	expected *udpClientState,
	destination netip.AddrPort,
) bool {
	shard := t.clientShard(key)
	shard.access.RLock()
	defer shard.access.RUnlock()
	if shard.clients[key] != expected {
		return false
	}
	expected.access.Lock()
	defer expected.access.Unlock()
	if expected.closed {
		return false
	}
	if _, loaded := expected.bindings[destination]; loaded {
		return true
	}
	if expected.replyAliasCount >= udpReplyAliasLimit {
		return false
	}
	expected.bindings[destination] = udpRedirectBinding{replyAlias: true}
	expected.replyAliasCount++
	return true
}

func (t *udpClientTable) delete(key udpSessionKey, expected *udpClientState) []netip.Addr {
	shard := t.clientShard(key)
	shard.access.Lock()
	defer shard.access.Unlock()
	if shard.clients[key] != expected {
		return nil
	}
	delete(shard.clients, key)
	expected.access.Lock()
	redirects := make([]netip.Addr, 0, len(expected.cgroupOriginals))
	for address := range expected.cgroupOriginals {
		redirects = append(redirects, address)
	}
	expected.closed = true
	clear(expected.bindings)
	clear(expected.cgroupOriginals)
	expected.cgroupDataPlane = false
	expected.replyAliasCount = 0
	expected.access.Unlock()
	t.redirectAccess.Lock()
	for _, address := range redirects {
		lookupKey := udpRedirectSessionKey{client: key.Source, address: address}
		if t.redirectSessions[lookupKey] == key {
			delete(t.redirectSessions, lookupKey)
		}
	}
	t.redirectAccess.Unlock()
	return redirects
}

func (s *udpClientState) isCgroupDataPlane() bool {
	s.access.RLock()
	defer s.access.RUnlock()
	return s.cgroupDataPlane
}

func sourcePacketInfo(address netip.Addr) []byte {
	if address.Is4() {
		return (&ipv4.ControlMessage{Src: net.IP(address.AsSlice())}).Marshal()
	}
	return (&ipv6.ControlMessage{Src: net.IP(address.AsSlice())}).Marshal()
}

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
	create func(netip.AddrPort) (*net.UDPConn, error),
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
	socket, err := create(source)
	if err != nil {
		return nil, nil, err
	}
	entry := &udpReplySocketEntry{
		conn:   socket,
		writer: bufio.NewPacketBatchWriter(bufio.NewPacketConn(socket)),
	}
	entry.lastUsed.Store(time.Now().UnixNano())
	entry.inUse.Store(1)
	if p.closed.Load() {
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
			closeErr = errors.Join(closeErr, entry.conn.Close())
			delete(shard.sockets, source)
			p.stats.count.Add(-1)
		}
		shard.access.Unlock()
	}
	p.requestSweep()
	return closeErr
}

func (s *udpClientState) redirectBinding(destination netip.AddrPort) (udpRedirectBinding, bool) {
	s.access.RLock()
	binding, loaded := s.bindings[destination]
	s.access.RUnlock()
	return binding, loaded
}

func (s *udpClientState) hasAddressFamily(ipv4 bool) bool {
	s.access.RLock()
	defer s.access.RUnlock()
	if s.replyAliasCount >= udpReplyAliasLimit {
		return false
	}
	for destination := range s.bindings {
		if destination.Addr().Is4() == ipv4 {
			return true
		}
	}
	return false
}

func (s *udpClientState) sourceMACAddress() net.HardwareAddr {
	s.access.RLock()
	defer s.access.RUnlock()
	return append(net.HardwareAddr(nil), s.sourceMAC...)
}

func (s *udpClientState) processSocketCookie() uint64 {
	s.access.RLock()
	defer s.access.RUnlock()
	return s.socketCookie
}
