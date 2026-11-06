//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	commonEBPF "github.com/CHIZI-0618/sing-ebpf"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"

	"golang.org/x/sys/unix"
)

type fakeCgroupRecoveryBackend struct {
	drops      atomic.Uint64
	dropPolls  atomic.Int32
	sweepCalls atomic.Int32
	swept      chan struct{}
	polled     chan struct{}
	sweepFunc  func() (commonEBPF.UDPRecoverySweepResult, error)
}

func (b *fakeCgroupRecoveryBackend) SweepUDPRecovery(time.Duration, uint32) (commonEBPF.UDPRecoverySweepResult, error) {
	b.sweepCalls.Add(1)
	result := commonEBPF.UDPRecoverySweepResult{Complete: true}
	var err error
	if b.sweepFunc != nil {
		result, err = b.sweepFunc()
	}
	if b.swept != nil {
		select {
		case b.swept <- struct{}{}:
		default:
		}
	}
	return result, err
}

func (b *fakeCgroupRecoveryBackend) DeleteUDPRecovery(netip.AddrPort, uint64, uint32, uint64) (bool, error) {
	return true, nil
}

func (b *fakeCgroupRecoveryBackend) UDPReleaseNotificationDrops() (uint64, error) {
	b.dropPolls.Add(1)
	if b.polled != nil {
		select {
		case b.polled <- struct{}{}:
		default:
		}
	}
	return b.drops.Load(), nil
}

func (b *fakeCgroupRecoveryBackend) IsClosed() bool {
	return false
}

type fakeCgroupRedirectBackend struct {
	present map[netip.AddrPort]commonEBPF.OriginalDestination
	deleted []netip.AddrPort
}

func (b *fakeCgroupRedirectBackend) LookupOriginal(_ uint8, destination netip.AddrPort) (commonEBPF.OriginalDestination, error) {
	if original, ok := b.present[destination]; ok {
		return original, nil
	}
	return commonEBPF.OriginalDestination{}, E.Cause(unix.ENOENT, "lookup original destination")
}

func (b *fakeCgroupRedirectBackend) DeleteRedirect(_ uint8, destination netip.AddrPort) error {
	b.deleted = append(b.deleted, destination)
	delete(b.present, destination)
	return nil
}

func (b *fakeCgroupRedirectBackend) IsClosed() bool {
	return false
}

type cgroupRecoverySweepOutcome struct {
	result commonEBPF.UDPRecoverySweepResult
	err    error
}

type countingCgroupRecoveryBackend struct {
	backend     *commonEBPF.CgroupBackend
	sweepCalls  atomic.Int32
	deleteCalls atomic.Int32
	swept       chan cgroupRecoverySweepOutcome
	deleted     chan struct{}
	polled      chan struct{}
}

func (b *countingCgroupRecoveryBackend) SweepUDPRecovery(maxIdle time.Duration, fallbackBudget uint32) (commonEBPF.UDPRecoverySweepResult, error) {
	b.sweepCalls.Add(1)
	result, err := b.backend.SweepUDPRecovery(maxIdle, fallbackBudget)
	if b.swept != nil {
		select {
		case b.swept <- cgroupRecoverySweepOutcome{result: result, err: err}:
		default:
		}
	}
	return result, err
}

func (b *countingCgroupRecoveryBackend) DeleteUDPRecovery(listenerDestination netip.AddrPort, socketCookie uint64, networkGeneration uint32, releasedAtNS uint64) (bool, error) {
	b.deleteCalls.Add(1)
	removed, err := b.backend.DeleteUDPRecovery(listenerDestination, socketCookie, networkGeneration, releasedAtNS)
	if b.deleted != nil {
		select {
		case b.deleted <- struct{}{}:
		default:
		}
	}
	return removed, err
}

func (b *countingCgroupRecoveryBackend) UDPReleaseNotificationDrops() (uint64, error) {
	drops, err := b.backend.UDPReleaseNotificationDrops()
	if b.polled != nil {
		select {
		case b.polled <- struct{}{}:
		default:
		}
	}
	return drops, err
}

func (b *countingCgroupRecoveryBackend) IsClosed() bool {
	return b.backend.IsClosed()
}

func waitFreshWatchdogPolls(t *testing.T, polled <-chan struct{}, count int) {
	t.Helper()
	for {
		select {
		case <-polled:
		default:
			goto wait
		}
	}
wait:
	for i := range count {
		select {
		case <-polled:
		case <-time.After(time.Second):
			t.Fatalf("timed out waiting for fresh idle watchdog poll %d/%d", i+1, count)
		}
	}
}

func waitCompleteSweep(t *testing.T, swept <-chan cgroupRecoverySweepOutcome) {
	t.Helper()
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	for {
		select {
		case outcome := <-swept:
			if outcome.err == nil && outcome.result.Complete {
				return
			}
		case <-timer.C:
			t.Fatal("timed out waiting for completed cgroup UDP recovery sweep")
		}
	}
}

func TestCgroupRecoverySchedulerSweepsStartupKernelDrops(t *testing.T) {
	backend := &fakeCgroupRecoveryBackend{
		swept: make(chan struct{}, 4),
	}
	backend.drops.Store(3)

	inbound := &Inbound{
		logger: logger.NOP(),
		inboundWorkers: inboundWorkers{
			cgroupRecoveryEvents:      make(chan commonEBPF.UDPReleaseEvent, 4),
			cgroupRecoverySweepWake:   make(chan struct{}, 1),
			cgroupRecoveryExpiryWake:  make(chan struct{}, 1),
			cgroupRecoveryReaderError: make(chan struct{}, 1),
		},
	}

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	timing := cgroupRecoveryTiming{
		maxIdle:          40 * time.Millisecond,
		continuation:     10 * time.Millisecond,
		fallbackInterval: 50 * time.Millisecond,
		watchdogInterval: 10 * time.Millisecond,
	}
	go inbound.runCgroupRecoverySchedulerLoop(ctx, backend, done, timing)
	t.Cleanup(func() {
		cancel()
		<-done
	})

	// Expect an immediate watchdog sweep for the pre-existing startup drop count
	// plus the follow-up sweep after maxIdle.
	for i := range 2 {
		select {
		case <-backend.swept:
		case <-time.After(time.Second):
			t.Fatalf("timed out waiting for startup kernel-drop sweep %d (sweeps=%d polls=%d)", i+1, backend.sweepCalls.Load(), backend.dropPolls.Load())
		}
	}
}

func TestCgroupRecoverySchedulerSkipsSweepWhenHealthy(t *testing.T) {
	backend := &fakeCgroupRecoveryBackend{
		polled: make(chan struct{}, 8),
	}

	inbound := &Inbound{
		logger: logger.NOP(),
		inboundWorkers: inboundWorkers{
			cgroupRecoveryEvents:      make(chan commonEBPF.UDPReleaseEvent, 4),
			cgroupRecoverySweepWake:   make(chan struct{}, 1),
			cgroupRecoveryExpiryWake:  make(chan struct{}, 1),
			cgroupRecoveryReaderError: make(chan struct{}, 1),
		},
	}

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	timing := cgroupRecoveryTiming{
		maxIdle:          40 * time.Millisecond,
		continuation:     10 * time.Millisecond,
		fallbackInterval: 50 * time.Millisecond,
		watchdogInterval: 10 * time.Millisecond,
	}
	go inbound.runCgroupRecoverySchedulerLoop(ctx, backend, done, timing)
	t.Cleanup(func() {
		cancel()
		<-done
	})

	waitFreshWatchdogPolls(t, backend.polled, 6)
	cancel()
	<-done

	if got := backend.sweepCalls.Load(); got != 0 {
		t.Fatalf("healthy ring-buffer scheduler ran %d unexpected map sweeps", got)
	}
}

func TestCgroupRecoverySchedulerSweepsUserspaceDeletedRedirects(t *testing.T) {
	backend := &fakeCgroupRecoveryBackend{
		swept:  make(chan struct{}, 8),
		polled: make(chan struct{}, 16),
	}

	inbound := &Inbound{
		logger: logger.NOP(),
		inboundWorkers: inboundWorkers{
			cgroupRecoveryEvents:      make(chan commonEBPF.UDPReleaseEvent, 4),
			cgroupRecoverySweepWake:   make(chan struct{}, 1),
			cgroupRecoveryExpiryWake:  make(chan struct{}, 1),
			cgroupRecoveryReaderError: make(chan struct{}, 1),
		},
	}

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	timing := cgroupRecoveryTiming{
		maxIdle:          80 * time.Millisecond,
		continuation:     10 * time.Millisecond,
		fallbackInterval: 50 * time.Millisecond,
		watchdogInterval: 10 * time.Millisecond,
	}
	go inbound.runCgroupRecoverySchedulerLoop(ctx, backend, done, timing)
	t.Cleanup(func() {
		cancel()
		<-done
	})

	// Schedule first expiry wave, confirm the scheduler loop has consumed it
	// (expiryWake drained and one subsequent watchdog tick observed), then
	// schedule a second wave mid-window: the second must not starve the first,
	// and both waves must complete before returning to zero-scan.
	inbound.requestCgroupRecoveryExpirySweep()
	deadline := time.Now().Add(time.Second)
	for len(inbound.cgroupRecoveryExpiryWake) > 0 {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for scheduler to consume first expiry wake")
		}
		time.Sleep(time.Millisecond)
	}
	waitFreshWatchdogPolls(t, backend.polled, 1)
	inbound.requestCgroupRecoveryExpirySweep()

	for i := range 2 {
		select {
		case <-backend.swept:
		case <-time.After(time.Second):
			t.Fatalf("timed out waiting for userspace redirect expiry sweep %d (sweeps=%d)", i+1, backend.sweepCalls.Load())
		}
	}

	sweepsAfterExpiry := backend.sweepCalls.Load()
	// Drain stale buffered polls and observe an idle window strictly longer than maxIdle.
	waitFreshWatchdogPolls(t, backend.polled, 10)
	cancel()
	<-done

	if got := backend.sweepCalls.Load(); got != sweepsAfterExpiry {
		t.Fatalf("scheduler continued sweeping after expiry completed: before=%d after=%d", sweepsAfterExpiry, got)
	}
}

func TestCgroupRecoverySchedulerConsumesPendingPreStartExpirySweep(t *testing.T) {
	backend := &fakeCgroupRecoveryBackend{
		swept:  make(chan struct{}, 4),
		polled: make(chan struct{}, 32),
		sweepFunc: func() (commonEBPF.UDPRecoverySweepResult, error) {
			return commonEBPF.UDPRecoverySweepResult{Complete: true}, nil
		},
	}

	// Simulate a UDP redirect deleted during the startup window between listener
	// start and startCgroupRecoveryScheduler(), while expiryWake is still nil.
	inbound := &Inbound{logger: logger.NOP()}
	inbound.requestCgroupRecoveryExpirySweep()

	inbound.cgroupRecoveryAccess.Lock()
	inbound.cgroupRecoveryEvents = make(chan commonEBPF.UDPReleaseEvent, 4)
	inbound.cgroupRecoverySweepWake = make(chan struct{}, 1)
	inbound.cgroupRecoveryExpiryWake = make(chan struct{}, 1)
	inbound.cgroupRecoveryReaderError = make(chan struct{}, 1)
	inbound.cgroupRecoveryAccess.Unlock()

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	timing := cgroupRecoveryTiming{
		maxIdle:          30 * time.Millisecond,
		continuation:     10 * time.Millisecond,
		fallbackInterval: 50 * time.Millisecond,
		watchdogInterval: 10 * time.Millisecond,
	}
	go inbound.runCgroupRecoverySchedulerLoop(ctx, backend, done, timing)
	t.Cleanup(func() {
		cancel()
		<-done
	})

	select {
	case <-backend.swept:
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for pre-start pending expiry sweep (sweeps=%d)", backend.sweepCalls.Load())
	}

	sweepsAfterExpiry := backend.sweepCalls.Load()
	waitFreshWatchdogPolls(t, backend.polled, 6)
	cancel()
	<-done

	if got := backend.sweepCalls.Load(); got != sweepsAfterExpiry {
		t.Fatalf("scheduler continued sweeping after pre-start pending expiry completed: before=%d after=%d", sweepsAfterExpiry, got)
	}
}

func TestCgroupRecoverySchedulerPaginatedExpiryCompletesFullPass(t *testing.T) {
	timing := cgroupRecoveryTiming{
		maxIdle:          30 * time.Millisecond,
		continuation:     80 * time.Millisecond,
		fallbackInterval: 100 * time.Millisecond,
		watchdogInterval: 10 * time.Millisecond,
	}

	var mu sync.Mutex
	var cursor int
	page0 := make(map[string]time.Time)
	page0Done := make(chan struct{}, 8)
	passDone := make(chan struct{}, 8)

	backend := &fakeCgroupRecoveryBackend{
		polled: make(chan struct{}, 32),
		sweepFunc: func() (commonEBPF.UDPRecoverySweepResult, error) {
			mu.Lock()
			defer mu.Unlock()
			if cursor == 0 {
				now := time.Now()
				var removed uint32
				for key, expiry := range page0 {
					if !expiry.After(now) {
						delete(page0, key)
						removed++
					}
				}
				cursor = 1
				select {
				case page0Done <- struct{}{}:
				default:
				}
				return commonEBPF.UDPRecoverySweepResult{Scanned: 1024, Removed: removed, Complete: false}, nil
			}
			cursor = 0
			select {
			case passDone <- struct{}{}:
			default:
			}
			return commonEBPF.UDPRecoverySweepResult{Scanned: 1, Complete: true}, nil
		},
	}

	inbound := &Inbound{
		logger: logger.NOP(),
		inboundWorkers: inboundWorkers{
			cgroupRecoveryEvents:      make(chan commonEBPF.UDPReleaseEvent, 4),
			cgroupRecoverySweepWake:   make(chan struct{}, 1),
			cgroupRecoveryExpiryWake:  make(chan struct{}, 1),
			cgroupRecoveryReaderError: make(chan struct{}, 1),
		},
	}

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go inbound.runCgroupRecoverySchedulerLoop(ctx, backend, done, timing)
	t.Cleanup(func() {
		cancel()
		<-done
	})

	// Wave 1 and Wave 2 both live on page 0. Wait deterministically until pass 1
	// has swept page 0 (reclaiming wave 1 and leaving cursor at page 1 while
	// waiting for the 80ms continuation), then add wave 2 with a 30ms maxIdle so
	// wave 2 expires while pass 1 is still in flight. The scheduler must finish
	// pass 1 and then start a fresh full pass from cursor 0 to reclaim wave 2.
	mu.Lock()
	page0["wave1"] = time.Now().Add(timing.maxIdle)
	mu.Unlock()
	inbound.requestCgroupRecoveryExpirySweep()

	select {
	case <-page0Done:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for pass 1 to sweep page 0")
	}

	mu.Lock()
	page0["wave2"] = time.Now().Add(timing.maxIdle)
	mu.Unlock()
	inbound.requestCgroupRecoveryExpirySweep()

	// Expect two complete full passes: pass 1 reclaims wave 1, pass 2 starts from
	// cursor 0 after wave 2 expires and reclaims wave 2.
	for i := range 2 {
		select {
		case <-passDone:
		case <-time.After(time.Second):
			mu.Lock()
			remaining := len(page0)
			mu.Unlock()
			t.Fatalf("timed out waiting for completed paginated sweep pass %d (sweeps=%d remaining=%d)", i+1, backend.sweepCalls.Load(), remaining)
		}
	}

	mu.Lock()
	remaining := len(page0)
	mu.Unlock()
	if remaining != 0 {
		t.Fatalf("paginated expiry sweep left %d expired entries unreclaimed", remaining)
	}

	sweepsAfterPasses := backend.sweepCalls.Load()
	waitFreshWatchdogPolls(t, backend.polled, 6)
	cancel()
	<-done

	if got := backend.sweepCalls.Load(); got != sweepsAfterPasses {
		t.Fatalf("scheduler continued sweeping after paginated expiry completed: before=%d after=%d", sweepsAfterPasses, got)
	}
}

func TestDeleteCgroupUDPRedirectsOnlyWakesWhenPresent(t *testing.T) {
	const listenerPort uint16 = 12345
	addrAbsent := netip.MustParseAddr("127.64.0.10")
	addrPresent := netip.MustParseAddr("127.64.0.11")

	newInbound := func() *Inbound {
		inbound := &Inbound{
			logger: logger.NOP(),
			inboundWorkers: inboundWorkers{
				cgroupRecoveryExpiryWake: make(chan struct{}, 1),
			},
		}
		inbound.listeners.port = listenerPort
		return inbound
	}

	t.Run("all_absent_skips_delete_and_wake", func(t *testing.T) {
		inbound := newInbound()
		backend := &fakeCgroupRedirectBackend{present: map[netip.AddrPort]commonEBPF.OriginalDestination{}}
		inbound.deleteCgroupUDPRedirectsWith(backend, []netip.Addr{addrAbsent})
		if len(backend.deleted) != 0 {
			t.Fatalf("unexpected DeleteRedirect calls for kernel-deleted entries: %v", backend.deleted)
		}
		select {
		case <-inbound.cgroupRecoveryExpiryWake:
			t.Fatal("unexpected expiry sweep wake when no redirect existed")
		default:
		}
	})

	t.Run("present_deletes_and_wakes", func(t *testing.T) {
		inbound := newInbound()
		keyPresent := netip.AddrPortFrom(addrPresent, listenerPort)
		backend := &fakeCgroupRedirectBackend{
			present: map[netip.AddrPort]commonEBPF.OriginalDestination{
				keyPresent: {Destination: netip.MustParseAddrPort("203.0.113.9:53")},
			},
		}
		inbound.deleteCgroupUDPRedirectsWith(backend, []netip.Addr{addrAbsent, addrPresent})
		if len(backend.deleted) != 1 || backend.deleted[0] != keyPresent {
			t.Fatalf("deleted redirects = %v, want [%v]", backend.deleted, keyPresent)
		}
		select {
		case <-inbound.cgroupRecoveryExpiryWake:
		default:
			t.Fatal("expected expiry sweep wake after userspace DeleteRedirect")
		}
	})
}

func prepareTestCgroupBackend(t *testing.T, listenerPort uint16) *commonEBPF.CgroupBackend {
	t.Helper()
	selfBypass, err := commonEBPF.NewSelfBypassWithCapacity(commonEBPF.CompactSelfBypassSocketCapacity)
	if err != nil {
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.ENOSYS) {
			t.Skipf("kernel BPF map creation unavailable: %v", err)
		}
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = selfBypass.Close() })

	backend, err := commonEBPF.PrepareCgroup(commonEBPF.CgroupConfig{
		EnableUDP:    true,
		RedirectIPv4: netip.MustParsePrefix("127.64.0.0/10"),
		MapCapacity:  commonEBPF.CompactCgroupMapCapacity(),
		UDPTimeout:   time.Minute,
		SelfBypass:   selfBypass,
	})
	if err != nil {
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.ENOSYS) {
			t.Skipf("kernel BPF map creation unavailable: %v", err)
		}
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })

	if err = backend.LoadPrograms(listenerPort); err != nil {
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.ENOSYS) {
			t.Skipf("kernel BPF program/map creation unavailable: %v", err)
		}
		t.Fatal(err)
	}
	return backend
}

func TestCgroupRecoveryNormalReleaseSkipsSweep(t *testing.T) {
	const listenerPort uint16 = 12345
	timing := cgroupRecoveryTiming{
		maxIdle:          40 * time.Millisecond,
		continuation:     10 * time.Millisecond,
		fallbackInterval: 50 * time.Millisecond,
		watchdogInterval: 10 * time.Millisecond,
	}

	waitClientTableEmpty := func(t *testing.T, inbound *Inbound) {
		t.Helper()
		deadline := time.Now().Add(time.Second)
		for time.Now().Before(deadline) {
			if inbound.udpClientTable.count() == 0 {
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
		t.Fatalf("udpClientTable still tracks %d clients after ReleaseSocket", inbound.udpClientTable.count())
	}

	t.Run("connected_release_skips_sweep", func(t *testing.T) {
		backend := prepareTestCgroupBackend(t, listenerPort)
		counting := &countingCgroupRecoveryBackend{
			backend: backend,
			swept:   make(chan cgroupRecoverySweepOutcome, 16),
			deleted: make(chan struct{}, 4),
			polled:  make(chan struct{}, 32),
		}

		connections := make(chan udpNATTestConnection, 1)
		inbound := &Inbound{
			ctx:    t.Context(),
			logger: logger.NOP(),
			inboundWorkers: inboundWorkers{
				cgroupRecoveryEvents:      make(chan commonEBPF.UDPReleaseEvent, 4),
				cgroupRecoverySweepWake:   make(chan struct{}, 1),
				cgroupRecoveryExpiryWake:  make(chan struct{}, 1),
				cgroupRecoveryReaderError: make(chan struct{}, 1),
			},
		}
		inbound.listeners.port = listenerPort
		inbound.setCgroupBackend(backend)
		inbound.udpNat = newUDPNATService(&udpNATTestHandler{connections: connections}, inbound.preparePacketConnection, time.Minute)
		t.Cleanup(func() { _ = inbound.udpNat.Close() })

		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan struct{})
		go inbound.runCgroupRecoverySchedulerLoop(ctx, counting, done, timing)
		t.Cleanup(func() {
			cancel()
			<-done
		})

		const cookie uint64 = 4242
		client := netip.MustParseAddrPort("127.0.0.1:53100")
		origin := netip.MustParseAddrPort("203.0.113.9:53")
		redirect := netip.MustParseAddr("127.64.0.10")
		key := udpSessionKey{Source: client, Scope: udpSessionScopeLocalCgroup, SocketCookie: cookie}

		// Record the active connected UDP session. Its redirect is intentionally
		// absent from cgroup_udp_redirect, matching kernel sock_release having
		// already deleted it before emitting the ring-buffer release event.
		inbound.udpClientTable.setCgroupBinding(key, commonEBPF.OriginalDestination{
			Destination:  origin,
			SocketCookie: cookie,
			ConnectedUDP: true,
		}, redirect)
		inbound.udpNat.NewPacket(key, [][]byte{[]byte("hi")}, M.SocksaddrFromNetIP(client), M.SocksaddrFromNetIP(origin), nil)
		receiveUDPNATTestConnection(t, connections)

		inbound.udpNat.ReleaseSocket(cookie)
		inbound.enqueueCgroupRecoveryEvent(commonEBPF.UDPReleaseEvent{
			Listener:     netip.AddrPortFrom(redirect, listenerPort),
			SocketCookie: cookie,
		})

		waitClientTableEmpty(t, inbound)
		select {
		case <-counting.deleted:
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for per-key DeleteUDPRecovery after normal release event")
		}

		waitFreshWatchdogPolls(t, counting.polled, 6)
		cancel()
		<-done

		if got := counting.sweepCalls.Load(); got != 0 {
			t.Fatalf("normal connected UDP socket release triggered %d unexpected map sweeps", got)
		}
	})

	t.Run("release_with_reply_alias_reclaims_alias", func(t *testing.T) {
		backend := prepareTestCgroupBackend(t, listenerPort)
		counting := &countingCgroupRecoveryBackend{
			backend: backend,
			swept:   make(chan cgroupRecoverySweepOutcome, 16),
			deleted: make(chan struct{}, 4),
			polled:  make(chan struct{}, 32),
		}

		connections := make(chan udpNATTestConnection, 1)
		inbound := &Inbound{
			ctx:    t.Context(),
			logger: logger.NOP(),
			inboundWorkers: inboundWorkers{
				cgroupRecoveryEvents:      make(chan commonEBPF.UDPReleaseEvent, 4),
				cgroupRecoverySweepWake:   make(chan struct{}, 1),
				cgroupRecoveryExpiryWake:  make(chan struct{}, 1),
				cgroupRecoveryReaderError: make(chan struct{}, 1),
			},
		}
		inbound.listeners.port = listenerPort
		inbound.setCgroupBackend(backend)
		inbound.udpNat = newUDPNATService(&udpNATTestHandler{connections: connections}, inbound.preparePacketConnection, time.Minute)
		t.Cleanup(func() { _ = inbound.udpNat.Close() })

		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan struct{})
		go inbound.runCgroupRecoverySchedulerLoop(ctx, counting, done, timing)
		t.Cleanup(func() {
			cancel()
			<-done
		})

		const cookie uint64 = 4243
		client := netip.MustParseAddrPort("127.0.0.1:53101")
		origin := netip.MustParseAddrPort("203.0.113.9:53")
		aliasDestination := netip.MustParseAddrPort("203.0.113.10:53")
		redirect := netip.MustParseAddr("127.64.0.11")
		key := udpSessionKey{Source: client, Scope: udpSessionScopeLocalCgroup, SocketCookie: cookie}

		inbound.udpClientTable.setCgroupBinding(key, commonEBPF.OriginalDestination{
			Destination:  origin,
			SocketCookie: cookie,
			ConnectedUDP: true,
		}, redirect)
		inbound.udpNat.NewPacket(key, [][]byte{[]byte("hi")}, M.SocksaddrFromNetIP(client), M.SocksaddrFromNetIP(origin), nil)
		receiveUDPNATTestConnection(t, connections)

		clientState, loaded := inbound.udpClientTable.load(key)
		if !loaded {
			t.Fatal("missing UDP client state for active NAT session")
		}
		aliasRedirect, err := backend.ReserveUDPReplyRedirect(aliasDestination, listenerPort)
		if err != nil {
			t.Fatal(err)
		}
		if !inbound.udpClientTable.setCgroupReplyBinding(key, clientState, aliasDestination, aliasRedirect) {
			t.Fatal("failed to attach cgroup reply alias to active NAT session")
		}

		inbound.udpNat.ReleaseSocket(cookie)
		inbound.enqueueCgroupRecoveryEvent(commonEBPF.UDPReleaseEvent{
			Listener:     netip.AddrPortFrom(redirect, listenerPort),
			SocketCookie: cookie,
		})

		waitClientTableEmpty(t, inbound)
		waitCompleteSweep(t, counting.swept)

		recovered, err := backend.RecoverUDPOriginal(netip.AddrPortFrom(aliasRedirect, listenerPort))
		if !errors.Is(err, unix.ENOENT) {
			t.Fatalf("reply alias was not reclaimed after maxIdle: recovered=%+v err=%v", recovered, err)
		}

		sweepsAfterReclaim := counting.sweepCalls.Load()
		waitFreshWatchdogPolls(t, counting.polled, 6)
		cancel()
		<-done

		if got := counting.sweepCalls.Load(); got != sweepsAfterReclaim {
			t.Fatalf("scheduler continued sweeping after reply alias reclaim: before=%d after=%d", sweepsAfterReclaim, got)
		}
	})
}

func TestCgroupRecoveryReclaimsUserspaceDeletedRedirect(t *testing.T) {
	const listenerPort uint16 = 12345
	backend := prepareTestCgroupBackend(t, listenerPort)

	origin := netip.MustParseAddrPort("203.0.113.9:53")
	redirect, err := backend.ReserveUDPReplyRedirect(origin, listenerPort)
	if err != nil {
		t.Fatal(err)
	}

	counting := &countingCgroupRecoveryBackend{
		backend: backend,
		swept:   make(chan cgroupRecoverySweepOutcome, 16),
		polled:  make(chan struct{}, 32),
	}

	inbound := &Inbound{
		logger: logger.NOP(),
		inboundWorkers: inboundWorkers{
			cgroupRecoveryEvents:      make(chan commonEBPF.UDPReleaseEvent, 4),
			cgroupRecoverySweepWake:   make(chan struct{}, 1),
			cgroupRecoveryExpiryWake:  make(chan struct{}, 1),
			cgroupRecoveryReaderError: make(chan struct{}, 1),
		},
	}
	inbound.listeners.port = listenerPort
	inbound.setCgroupBackend(backend)

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	timing := cgroupRecoveryTiming{
		maxIdle:          40 * time.Millisecond,
		continuation:     10 * time.Millisecond,
		fallbackInterval: 50 * time.Millisecond,
		watchdogInterval: 10 * time.Millisecond,
	}
	go inbound.runCgroupRecoverySchedulerLoop(ctx, counting, done, timing)
	t.Cleanup(func() {
		cancel()
		<-done
	})

	// Simulate NAT idle-timeout cleanup calling DeleteRedirect in userspace.
	// This moves the redirect into sb_cg_recover without emitting a ringbuf event.
	inbound.deleteCgroupUDPRedirects([]netip.Addr{redirect})

	waitCompleteSweep(t, counting.swept)

	recovered, err := backend.RecoverUDPOriginal(netip.AddrPortFrom(redirect, listenerPort))
	if !errors.Is(err, unix.ENOENT) {
		t.Fatalf("userspace-deleted redirect was not reclaimed after maxIdle: recovered=%+v err=%v", recovered, err)
	}
}

func TestCgroupRecoveryReclaimsAfterNetworkHandover(t *testing.T) {
	const listenerPort uint16 = 12345
	backend := prepareTestCgroupBackend(t, listenerPort)
	if err := backend.ResetNetworkState(); err != nil {
		t.Fatal(err)
	}

	// Seed sb_cg_recover before starting the scheduler, representing an entry
	// written under network generation 1 whose per-key DeleteUDPRecovery will be
	// skipped once InterfaceUpdated advances the generation to 2.
	origin := netip.MustParseAddrPort("203.0.113.12:53")
	redirect, err := backend.ReserveUDPReplyRedirect(origin, listenerPort)
	if err != nil {
		t.Fatal(err)
	}
	if err = backend.DeleteRedirect(commonEBPF.ProtocolUDP, netip.AddrPortFrom(redirect, listenerPort)); err != nil {
		t.Fatal(err)
	}

	counting := &countingCgroupRecoveryBackend{
		backend: backend,
		swept:   make(chan cgroupRecoverySweepOutcome, 16),
		deleted: make(chan struct{}, 4),
		polled:  make(chan struct{}, 32),
	}

	defaultMonitor := &testDefaultInterfaceMonitor{current: &control.Interface{Name: "rmnet_data0", Index: 19}}
	inbound := &Inbound{
		logger:         logger.NOP(),
		networkManager: &testInterfaceNetworkManager{defaultMonitor: defaultMonitor},
		inboundWorkers: inboundWorkers{
			cgroupRecoveryEvents:      make(chan commonEBPF.UDPReleaseEvent, 4),
			cgroupRecoverySweepWake:   make(chan struct{}, 1),
			cgroupRecoveryExpiryWake:  make(chan struct{}, 1),
			cgroupRecoveryReaderError: make(chan struct{}, 1),
		},
	}
	inbound.listeners.port = listenerPort
	inbound.setCgroupBackend(backend)

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	timing := cgroupRecoveryTiming{
		maxIdle:          40 * time.Millisecond,
		continuation:     10 * time.Millisecond,
		fallbackInterval: 50 * time.Millisecond,
		watchdogInterval: 10 * time.Millisecond,
	}
	go inbound.runCgroupRecoverySchedulerLoop(ctx, counting, done, timing)
	t.Cleanup(func() {
		cancel()
		<-done
	})

	// Enqueue a prior-generation release event, then trigger a network handover
	// before maxIdle expires so per-key DeleteUDPRecovery skips it on generation
	// mismatch (returning false, nil before map lookup). InterfaceUpdated must
	// schedule a coalesced expiry sweep that reclaims the real sb_cg_recover entry.
	inbound.enqueueCgroupRecoveryEvent(commonEBPF.UDPReleaseEvent{
		Listener:          netip.AddrPortFrom(redirect, listenerPort),
		SocketCookie:      4244,
		NetworkGeneration: 1,
	})
	inbound.InterfaceUpdated(t.Context())

	select {
	case <-counting.deleted:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for prior-generation DeleteUDPRecovery attempt")
	}
	waitCompleteSweep(t, counting.swept)

	recovered, err := backend.RecoverUDPOriginal(netip.AddrPortFrom(redirect, listenerPort))
	if !errors.Is(err, unix.ENOENT) {
		t.Fatalf("prior-generation recovery entry was not reclaimed after network handover: recovered=%+v err=%v", recovered, err)
	}

	sweepsAfterHandover := counting.sweepCalls.Load()
	waitFreshWatchdogPolls(t, counting.polled, 6)
	cancel()
	<-done

	if got := counting.sweepCalls.Load(); got != sweepsAfterHandover {
		t.Fatalf("scheduler continued sweeping after handover reclaim: before=%d after=%d", sweepsAfterHandover, got)
	}
}
