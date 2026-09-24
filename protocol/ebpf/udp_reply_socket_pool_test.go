//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func newLoopbackUDPSocket(netip.AddrPort) (*net.UDPConn, func(), error) {
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	return socket, nil, err
}

func TestUDPReplySocketPoolRunsSocketCleanup(t *testing.T) {
	var pool udpReplySocketPool
	var cleaned atomic.Int32
	create := func(netip.AddrPort) (*net.UDPConn, func(), error) {
		socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		return socket, func() { cleaned.Add(1) }, err
	}
	destination := netip.MustParseAddrPort("203.0.113.1:53")
	_, release, err := pool.get(destination, create)
	if err != nil {
		t.Fatal(err)
	}
	release()
	if err = pool.reset(); err != nil {
		t.Fatal(err)
	}
	if actual := cleaned.Load(); actual != 1 {
		t.Fatalf("cleanup count after reset = %d, want 1", actual)
	}
	_, release, err = pool.get(destination, create)
	if err != nil {
		t.Fatal(err)
	}
	release()
	if err = pool.close(); err != nil {
		t.Fatal(err)
	}
	if actual := cleaned.Load(); actual != 2 {
		t.Fatalf("cleanup count after close = %d, want 2", actual)
	}
}

// destinationOnShard builds a distinct destination address:port whose
// shardIndex is exactly shard, so a test can target one shard's capacity
// without depending on how many other shards happen to collide.
func destinationOnShard(pool *udpReplySocketPool, shard int, ordinal int) netip.AddrPort {
	for port := 1; port < 65535; port++ {
		candidate := netip.AddrPortFrom(netip.MustParseAddr("203.0.113.1"), uint16(port))
		if pool.shardIndex(candidate) == shard {
			if ordinal == 0 {
				return candidate
			}
			ordinal--
		}
	}
	panic("could not find enough distinct ports on the requested shard")
}

// TestUDPReplySocketPoolBoundsGlobalCapacity proves one busy shard can use the
// available pool while the global limit still bounds all sockets together.
func TestUDPReplySocketPoolBoundsGlobalCapacity(t *testing.T) {
	pool := udpReplySocketPool{capacity: 32}
	var releases []func()
	t.Cleanup(func() {
		for _, release := range releases {
			release()
		}
		_ = pool.close()
	})

	for i := 0; i < int(pool.socketCapacity()); i++ {
		_, release, err := pool.get(destinationOnShard(&pool, 0, i), newLoopbackUDPSocket)
		if err != nil {
			t.Fatalf("get %d: %v", i, err)
		}
		releases = append(releases, release)
	}
	if got := pool.snapshot().Count; got != pool.socketCapacity() {
		t.Fatalf("pool count = %d, want exactly the global capacity %d", got, pool.socketCapacity())
	}

	_, _, err := pool.get(destinationOnShard(&pool, 1, 0), newLoopbackUDPSocket)
	if err == nil {
		t.Fatal("pool accepted a socket past its global capacity while every existing one was still in use")
	}
	if rejected := pool.snapshot().CapacityRejected; rejected != 1 {
		t.Fatalf("capacityRejected = %d, want 1", rejected)
	}
}

// TestUDPReplySocketPoolEvictsIdleUnderPressure proves a full pool can reclaim
// an idle socket from a different shard to admit a new destination.
func TestUDPReplySocketPoolEvictsIdleUnderPressure(t *testing.T) {
	pool := udpReplySocketPool{capacity: 32}
	t.Cleanup(func() { _ = pool.close() })

	for i := 0; i < int(pool.socketCapacity()); i++ {
		_, release, err := pool.get(destinationOnShard(&pool, 1, i), newLoopbackUDPSocket)
		if err != nil {
			t.Fatalf("get %d: %v", i, err)
		}
		release() // idle immediately: nothing is "in flight" on it
	}

	extra := destinationOnShard(&pool, 2, 0)
	_, release, err := pool.get(extra, newLoopbackUDPSocket)
	if err != nil {
		t.Fatalf("pool refused a new destination despite having idle sockets to reclaim: %v", err)
	}
	release()

	snapshot := pool.snapshot()
	if snapshot.Count != pool.socketCapacity() {
		t.Fatalf("pool count = %d, want it to stay at the global capacity %d after eviction", snapshot.Count, pool.socketCapacity())
	}
	if snapshot.Evicted < 1 {
		t.Fatal("evicted counter did not increase for the reclaim that just happened")
	}
	if snapshot.CapacityRejected != 0 {
		t.Fatalf("capacityRejected = %d, want 0 — an idle socket was available to reclaim", snapshot.CapacityRejected)
	}
}

// TestUDPReplySocketPoolNeverEvictsAnInUseSocket is the concurrent-use
// protection requirement directly: a socket held by an in-flight send (its
// release func not yet called) must survive both capacity-triggered eviction
// and the idle sweeper, even when every timing signal says it looks idle.
func TestUDPReplySocketPoolNeverEvictsAnInUseSocket(t *testing.T) {
	pool := udpReplySocketPool{capacity: 32}
	t.Cleanup(func() { _ = pool.close() })

	inUseDestination := destinationOnShard(&pool, 2, 0)
	inUseEntry, holdRelease, err := pool.get(inUseDestination, newLoopbackUDPSocket)
	if err != nil {
		t.Fatalf("get the socket to hold in use: %v", err)
	}
	// holdRelease is deliberately not called yet: this simulates a send still
	// in flight on inUseSocket.

	// A zero idle timeout means every entry's lastUsed already qualifies as
	// idle; only the in-use guard should still be protecting inUseSocket.
	pool.sweepIdle(0)
	if got := pool.snapshot().Count; got != 1 {
		t.Fatalf("pool count = %d after sweeping with an in-flight socket held, want 1 (it must survive)", got)
	}
	if _, err = inUseEntry.conn.WriteToUDPAddrPort([]byte{1}, netip.MustParseAddrPort("127.0.0.1:9")); err != nil {
		t.Fatalf("the held-in-use socket was closed out from under the simulated send: %v", err)
	}

	// Filling the rest of the pool to capacity must also skip the in-use
	// entry when looking for something to reclaim.
	for i := 1; i < int(pool.socketCapacity()); i++ {
		_, release, getErr := pool.get(destinationOnShard(&pool, 2, i), newLoopbackUDPSocket)
		if getErr != nil {
			t.Fatalf("get %d: %v", i, getErr)
		}
		release()
	}
	extra := destinationOnShard(&pool, 3, 0)
	_, extraRelease, err := pool.get(extra, newLoopbackUDPSocket)
	if err != nil {
		t.Fatalf("shard could not admit a new destination by reclaiming an idle one: %v", err)
	}
	extraRelease()
	if _, err = inUseEntry.conn.WriteToUDPAddrPort([]byte{1}, netip.MustParseAddrPort("127.0.0.1:9")); err != nil {
		t.Fatalf("capacity-triggered eviction closed the in-use socket instead of an idle one: %v", err)
	}

	holdRelease()
}

// TestUDPReplySocketPoolSweepsIdleSockets proves the idle-timeout reclaim
// itself: a released (not in use) socket older than the given timeout is
// closed and removed, independent of any capacity pressure.
func TestUDPReplySocketPoolSweepsIdleSockets(t *testing.T) {
	var pool udpReplySocketPool
	t.Cleanup(func() { _ = pool.close() })

	destination := destinationOnShard(&pool, 3, 0)
	entry, release, err := pool.get(destination, newLoopbackUDPSocket)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	release()

	pool.sweepIdle(0) // zero timeout: this entry is immediately "idle enough"

	if got := pool.snapshot().Count; got != 0 {
		t.Fatalf("pool count = %d after an idle sweep, want 0", got)
	}
	if pool.snapshot().Evicted != 1 {
		t.Fatalf("evicted = %d, want 1", pool.snapshot().Evicted)
	}
	if _, err = entry.conn.WriteToUDPAddrPort([]byte{1}, netip.MustParseAddrPort("127.0.0.1:9")); err == nil {
		t.Fatal("socket the idle sweep should have closed is still usable")
	}
}

func TestUDPReplySocketPoolRefreshesLazyHeapDeadline(t *testing.T) {
	var pool udpReplySocketPool
	t.Cleanup(func() { _ = pool.close() })

	destination := destinationOnShard(&pool, 3, 0)
	entry, release, err := pool.get(destination, newLoopbackUDPSocket)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	release()

	idleTimeout := time.Second
	originalLastUsed := entry.scheduledLastUsed
	refreshedLastUsed := originalLastUsed + int64(500*time.Millisecond)
	entry.lastUsed.Store(refreshedLastUsed)
	next, available := pool.sweepIdleAt(time.Unix(0, originalLastUsed).Add(idleTimeout), idleTimeout)
	if !available {
		t.Fatal("refreshed entry did not retain a future heap deadline")
	}
	wantNext := time.Unix(0, refreshedLastUsed).Add(idleTimeout)
	if !next.Equal(wantNext) {
		t.Fatalf("next deadline = %v, want %v", next, wantNext)
	}
	if got := pool.snapshot().Count; got != 1 {
		t.Fatalf("pool count = %d after stale deadline correction, want 1", got)
	}

	pool.sweepIdleAt(wantNext, idleTimeout)
	if got := pool.snapshot().Count; got != 0 {
		t.Fatalf("pool count = %d at refreshed deadline, want 0", got)
	}
}

func TestUDPReplySocketPoolInUseRetryPreservesLastUsed(t *testing.T) {
	var pool udpReplySocketPool
	t.Cleanup(func() { _ = pool.close() })

	destination := destinationOnShard(&pool, 3, 0)
	entry, release, err := pool.get(destination, newLoopbackUDPSocket)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	lastUsed := entry.lastUsed.Load()
	idleTimeout := 5 * time.Minute
	now := time.Unix(0, lastUsed).Add(idleTimeout)
	next, available := pool.sweepIdleAt(now, idleTimeout)
	if !available {
		t.Fatal("in-use entry did not retain a retry deadline")
	}
	if got := entry.lastUsed.Load(); got != lastUsed {
		t.Fatalf("in-use retry changed lastUsed from %d to %d", lastUsed, got)
	}
	wantNext := now.Add(udpReplySocketInUseRetry)
	if !next.Equal(wantNext) {
		t.Fatalf("in-use retry deadline = %v, want %v", next, wantNext)
	}

	release()
	pool.sweepIdleAt(wantNext, idleTimeout)
	if got := pool.snapshot().Count; got != 0 {
		t.Fatalf("pool count = %d after in-use retry elapsed, want 0", got)
	}
}

func TestUDPReplySocketPoolReusesBatchWriter(t *testing.T) {
	var pool udpReplySocketPool
	t.Cleanup(func() { _ = pool.close() })

	destination := destinationOnShard(&pool, 3, 0)
	first, release, err := pool.get(destination, newLoopbackUDPSocket)
	if err != nil {
		t.Fatal(err)
	}
	release()
	second, release, err := pool.get(destination, newLoopbackUDPSocket)
	if err != nil {
		t.Fatal(err)
	}
	release()
	if first != second {
		t.Fatal("reply socket pool replaced an existing entry")
	}
	if first.writer == nil || first.writer != second.writer {
		t.Fatal("reply socket pool did not retain its packet batch writer")
	}
}

func TestUDPReplyBatchWriterRespectsGSOPolicy(t *testing.T) {
	receiver, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = receiver.Close() })
	if err = receiver.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	target := M.SocksaddrFromNetIP(receiver.LocalAddr().(*net.UDPAddr).AddrPort())

	for _, disabled := range []bool{false, true} {
		socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = socket.Close() })
		writer := newUDPReplyBatchWriter(socket, disabled)
		if N.IsGSODisabled(writer) != disabled {
			t.Fatalf("reply batch writer GSO policy lost: disabled=%v got=%v", disabled, N.IsGSODisabled(writer))
		}
		buffers := []*buf.Buffer{
			buf.As([]byte("batch-a")).ToOwned(),
			buf.As([]byte("batch-b")).ToOwned(),
		}
		if err = writer.WritePacketBatch(buffers, []M.Socksaddr{target, target}); err != nil {
			t.Fatalf("WritePacketBatch(disabled=%v): %v", disabled, err)
		}
		received := make(map[string]bool, 2)
		packet := make([]byte, 32)
		for range 2 {
			n, _, readErr := receiver.ReadFromUDPAddrPort(packet)
			if readErr != nil {
				t.Fatalf("ReadFromUDPAddrPort(disabled=%v): %v", disabled, readErr)
			}
			received[string(packet[:n])] = true
		}
		if !received["batch-a"] || !received["batch-b"] {
			t.Fatalf("unexpected received payloads (disabled=%v): %v", disabled, received)
		}
	}
}

func TestUDPReplySocketPoolRespectsGlobalGSODisable(t *testing.T) {
	const childEnv = "SING_BOX_TEST_EBPF_REPLY_GSO_CHILD"
	if mode := os.Getenv(childEnv); mode != "" {
		var pool udpReplySocketPool
		t.Cleanup(func() { _ = pool.close() })

		entry, release, err := pool.get(destinationOnShard(&pool, 2, 0), newLoopbackUDPSocket)
		if err != nil {
			t.Fatal(err)
		}
		defer release()

		wantDisabled := mode == "true"
		if N.IsGSODisabled(entry.writer) != wantDisabled {
			t.Fatalf("pool reply batch writer GSO disabled = %v, want %v (SING_BOX_DISABLE_GSO=%q)", N.IsGSODisabled(entry.writer), wantDisabled, os.Getenv("SING_BOX_DISABLE_GSO"))
		}
		return
	}

	baseEnv := make([]string, 0, len(os.Environ())+2)
	for _, entry := range os.Environ() {
		if strings.HasPrefix(entry, "SING_BOX_DISABLE_GSO=") || strings.HasPrefix(entry, childEnv+"=") {
			continue
		}
		baseEnv = append(baseEnv, entry)
	}
	for _, mode := range []string{"false", "true"} {
		cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestUDPReplySocketPoolRespectsGlobalGSODisable$")
		cmd.Env = append(append([]string(nil), baseEnv...), "SING_BOX_DISABLE_GSO="+mode, childEnv+"="+mode)
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("global SING_BOX_DISABLE_GSO=%s check failed: %v\n%s", mode, err, output)
		}
	}
}

// TestUDPReplySocketPoolStableUnderManyDestinations is the sustained-pressure
// check: hammering the pool with far more distinct destinations than its
// total capacity, immediately releasing each one (matching the real
// send-then-forget call pattern in tc_connection.go), must never let the
// pool's total footprint exceed its fixed bound.
//
// It does not assert zero get() errors: a real GitHub Actions run surfaced
// that, with `attempts` goroutines launched essentially at once racing
// across only udpClientShardCount shards, more goroutines can genuinely be
// simultaneously between get() returning and release() running on one shard
// than that shard's udpReplySocketShardCapacity -- pure scheduling luck
// under this much uncoordinated concurrency, not a bug in the pool. When
// that happens, get() correctly refuses rather than let the shard grow past
// its bound, which is exactly the guarantee this test exists to check. A
// capacity-rejection is therefore expected and tolerated; anything else
// (e.g. a real socket-creation failure) is still a hard failure, and every
// capacity-rejection get() returns must still show up in the pool's own
// CapacityRejected counter.
func TestUDPReplySocketPoolStableUnderManyDestinations(t *testing.T) {
	pool := udpReplySocketPool{capacity: 128}
	t.Cleanup(func() { _ = pool.close() })

	totalCapacity := int(pool.socketCapacity())
	attempts := totalCapacity * 4

	var wg sync.WaitGroup
	errs := make(chan error, attempts)
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			destination := netip.AddrPortFrom(netip.MustParseAddr("203.0.113.1"), uint16(1+i%65534))
			_, release, err := pool.get(destination, newLoopbackUDPSocket)
			if err != nil {
				errs <- fmt.Errorf("get %d: %w", i, err)
				return
			}
			release()
		}(i)
	}
	wg.Wait()
	close(errs)

	var rejected int64
	for err := range errs {
		if errors.Is(err, errUDPReplySocketCapacity) {
			rejected++
			continue
		}
		t.Error(err)
	}

	if got := pool.snapshot().Count; got > int64(totalCapacity) {
		t.Fatalf("pool count = %d, want at most the total capacity %d", got, totalCapacity)
	}
	if got := pool.snapshot().CapacityRejected; got != rejected {
		t.Fatalf("pool's own CapacityRejected counter = %d, but observed %d capacity errors from get() -- every rejection get() returns must be reflected in its own counter", got, rejected)
	}
}

func TestUDPReplySocketPoolReclaimsAtIdleDeadline(t *testing.T) {
	pool := udpReplySocketPool{idleTimeout: 20 * time.Millisecond}
	t.Cleanup(func() {
		pool.stopSweeper()
		_ = pool.close()
	})
	pool.startSweeper(context.Background())
	if _, release, err := pool.get(destinationOnShard(&pool, 4, 0), newLoopbackUDPSocket); err != nil {
		t.Fatalf("get: %v", err)
	} else {
		release()
	}

	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	for pool.snapshot().Count != 0 {
		select {
		case <-deadline.C:
			t.Fatal("idle socket was not reclaimed at its deadline")
		case <-time.After(5 * time.Millisecond):
		}
	}
}

// TestUDPReplySocketPoolSweeperStartStop confirms startSweeper/stopSweeper are
// idempotent and that stop waits for the deadline worker to exit.
func TestUDPReplySocketPoolSweeperStartStop(t *testing.T) {
	var pool udpReplySocketPool
	t.Cleanup(func() { _ = pool.close() })

	ctx := context.Background()
	pool.startSweeper(ctx)
	pool.startSweeper(ctx) // must be a no-op, not a second goroutine
	pool.stopSweeper()
	pool.stopSweeper() // must be safe to call again

	// The sweeper being stopped should not stop sweepIdle from still being
	// callable directly (reset()/close() do not depend on it).
	destination := destinationOnShard(&pool, 4, 0)
	if _, release, err := pool.get(destination, newLoopbackUDPSocket); err != nil {
		t.Fatalf("get after sweeper stop: %v", err)
	} else {
		release()
	}
	pool.sweepIdle(0)
	if got := pool.snapshot().Count; got != 0 {
		t.Fatalf("pool count = %d, want 0", got)
	}
}
