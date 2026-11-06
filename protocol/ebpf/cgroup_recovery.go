//go:build with_ebpf && (linux || android)

package ebpf

import (
	"container/heap"
	"context"
	"net/netip"
	"time"

	commonEBPF "github.com/CHIZI-0618/sing-ebpf"
)

type cgroupRecoveryBackend interface {
	SweepUDPRecovery(maxIdle time.Duration, fallbackBudget uint32) (commonEBPF.UDPRecoverySweepResult, error)
	DeleteUDPRecovery(listenerDestination netip.AddrPort, socketCookie uint64, networkGeneration uint32, releasedAtNS uint64) (bool, error)
	UDPReleaseNotificationDrops() (uint64, error)
	IsClosed() bool
}

type cgroupRecoveryTiming struct {
	maxIdle          time.Duration
	continuation     time.Duration
	fallbackInterval time.Duration
	watchdogInterval time.Duration
}

const (
	cgroupRecoveryMaxIdle          = 30 * time.Second
	cgroupRecoverySweepBudget      = 1024
	cgroupRecoveryQueueSize        = 1024
	cgroupRecoveryContinuation     = 100 * time.Millisecond
	cgroupRecoveryFallbackInterval = 10 * time.Second
	// Ring-buffer notifications are an acceleration path, not the ownership
	// source of truth. The watchdog reads the kernel loss counter; it schedules
	// a sweep only after observed loss. A reader failure explicitly switches to
	// the periodic compatibility fallback.
	cgroupRecoveryWatchdogInterval = 10 * time.Second
)

type cgroupRecoveryDeadline struct {
	event    commonEBPF.UDPReleaseEvent
	deadline time.Time
}

type cgroupRecoveryDeadlineHeap []cgroupRecoveryDeadline

func (h cgroupRecoveryDeadlineHeap) Len() int { return len(h) }
func (h cgroupRecoveryDeadlineHeap) Less(left, right int) bool {
	return h[left].deadline.Before(h[right].deadline)
}
func (h cgroupRecoveryDeadlineHeap) Swap(left, right int) { h[left], h[right] = h[right], h[left] }
func (h *cgroupRecoveryDeadlineHeap) Push(value any) {
	*h = append(*h, value.(cgroupRecoveryDeadline))
}
func (h *cgroupRecoveryDeadlineHeap) Pop() any {
	items := *h
	last := len(items) - 1
	entry := items[last]
	items[last] = cgroupRecoveryDeadline{}
	*h = items[:last]
	return entry
}

// startCgroupRecoveryScheduler uses release events and a deadline heap on the
// normal path. Kernels without release notifications retain a bounded,
// low-frequency sweep as the compatibility fallback.
func (i *Inbound) startCgroupRecoveryScheduler(backend *commonEBPF.CgroupBackend) {
	if backend == nil || i.udpTimeout <= 0 {
		return
	}
	i.cgroupRecoveryAccess.Lock()
	defer i.cgroupRecoveryAccess.Unlock()
	if i.cgroupRecoveryCancel != nil {
		return
	}
	ctx, cancel := context.WithCancel(i.ctx)
	done := make(chan struct{})
	i.cgroupRecoveryCancel = cancel
	i.cgroupRecoveryDone = done
	if backend.UDPUserspaceCleanupMode() == "ringbuf" {
		i.cgroupRecoveryEvents = make(chan commonEBPF.UDPReleaseEvent, cgroupRecoveryQueueSize)
		i.cgroupRecoverySweepWake = make(chan struct{}, 1)
		i.cgroupRecoveryExpiryWake = make(chan struct{}, 1)
		i.cgroupRecoveryReaderError = make(chan struct{}, 1)
		if i.cgroupRecoveryExpiryPending {
			i.cgroupRecoveryExpiryPending = false
			i.cgroupRecoveryExpiryWake <- struct{}{}
		}
	} else {
		i.cgroupRecoveryExpiryPending = false
	}
	go i.runCgroupRecoveryScheduler(ctx, backend, done)
}

func (i *Inbound) stopCgroupRecoveryScheduler() {
	i.cgroupRecoveryAccess.Lock()
	if i.cgroupRecoveryCancel == nil {
		i.cgroupRecoveryExpiryPending = false
		i.cgroupRecoveryAccess.Unlock()
		return
	}
	cancel := i.cgroupRecoveryCancel
	done := i.cgroupRecoveryDone
	i.cgroupRecoveryCancel = nil
	i.cgroupRecoveryDone = nil
	i.cgroupRecoveryAccess.Unlock()
	cancel()
	<-done
	i.cgroupRecoveryAccess.Lock()
	i.cgroupRecoveryEvents = nil
	i.cgroupRecoverySweepWake = nil
	i.cgroupRecoveryExpiryWake = nil
	i.cgroupRecoveryExpiryPending = false
	i.cgroupRecoveryReaderError = nil
	i.cgroupRecoveryAccess.Unlock()
}

func (i *Inbound) enqueueCgroupRecoveryEvent(event commonEBPF.UDPReleaseEvent) {
	i.cgroupRecoveryAccess.Lock()
	queue := i.cgroupRecoveryEvents
	if queue == nil {
		i.cgroupRecoveryAccess.Unlock()
		return
	}
	select {
	case queue <- event:
		i.cgroupRecoveryAccess.Unlock()
		return
	default:
	}
	i.cgroupRecoveryAccess.Unlock()
	i.cgroupRecoveryQueueOverflows.Add(1)
	i.cgroupRecoveryQueueOverflowAt.Store(time.Now().UnixNano())
	// A full queue means the event stream is incomplete. Coalesce recovery onto
	// the scheduler instead of scanning synchronously in the ring-buffer reader:
	// blocking that reader would amplify the same overflow we are recovering.
	i.requestCgroupRecoverySweep()
}

func (i *Inbound) requestCgroupRecoverySweep() {
	i.cgroupRecoveryAccess.Lock()
	wake := i.cgroupRecoverySweepWake
	i.cgroupRecoveryAccess.Unlock()
	if wake == nil {
		return
	}
	select {
	case wake <- struct{}{}:
	default:
	}
}

func (i *Inbound) requestCgroupRecoveryExpirySweep() {
	i.cgroupRecoveryAccess.Lock()
	wake := i.cgroupRecoveryExpiryWake
	if wake == nil {
		// Listeners start before Attach() starts the recovery scheduler; retain
		// pre-start requests so startup traffic rejected during that window is
		// still reclaimed once the scheduler initializes.
		i.cgroupRecoveryExpiryPending = true
		i.cgroupRecoveryAccess.Unlock()
		return
	}
	i.cgroupRecoveryAccess.Unlock()
	select {
	case wake <- struct{}{}:
	default:
	}
}

func (i *Inbound) signalCgroupRecoveryReaderError() {
	i.cgroupRecoveryAccess.Lock()
	readerError := i.cgroupRecoveryReaderError
	i.cgroupRecoveryAccess.Unlock()
	if readerError == nil {
		return
	}
	select {
	case readerError <- struct{}{}:
	default:
	}
}

func (i *Inbound) runCgroupRecoveryScheduler(ctx context.Context, backend *commonEBPF.CgroupBackend, done chan<- struct{}) {
	i.runCgroupRecoverySchedulerLoop(ctx, backend, done, cgroupRecoveryTiming{
		maxIdle:          cgroupRecoveryMaxIdle,
		continuation:     cgroupRecoveryContinuation,
		fallbackInterval: cgroupRecoveryFallbackInterval,
		watchdogInterval: cgroupRecoveryWatchdogInterval,
	})
}

func (i *Inbound) runCgroupRecoverySchedulerLoop(ctx context.Context, backend cgroupRecoveryBackend, done chan<- struct{}, timing cgroupRecoveryTiming) {
	defer close(done)
	i.cgroupRecoveryAccess.Lock()
	events := i.cgroupRecoveryEvents
	sweepWake := i.cgroupRecoverySweepWake
	expiryWake := i.cgroupRecoveryExpiryWake
	readerError := i.cgroupRecoveryReaderError
	pendingExpiry := i.cgroupRecoveryExpiryPending
	i.cgroupRecoveryExpiryPending = false
	i.cgroupRecoveryAccess.Unlock()
	if events == nil {
		i.runCgroupRecoveryFallback(ctx, backend, timing)
		return
	}
	if pendingExpiry && expiryWake != nil {
		select {
		case expiryWake <- struct{}{}:
		default:
		}
	}
	deadlines := make(cgroupRecoveryDeadlineHeap, 0, cgroupRecoveryQueueSize)
	heap.Init(&deadlines)
	timer := time.NewTimer(time.Hour)
	stopCgroupRecoveryTimer(timer)
	defer timer.Stop()
	watchdog := time.NewTicker(timing.watchdogInterval)
	defer watchdog.Stop()
	var fallbackTicker *time.Ticker
	var fallbackC <-chan time.Time
	defer func() {
		if fallbackTicker != nil {
			fallbackTicker.Stop()
		}
	}()
	var timerC <-chan time.Time
	continuation := time.NewTimer(time.Hour)
	stopCgroupRecoveryTimer(continuation)
	defer continuation.Stop()
	var continuationC <-chan time.Time
	lossFollowup := time.NewTimer(time.Hour)
	stopCgroupRecoveryTimer(lossFollowup)
	defer lossFollowup.Stop()
	var lossFollowupC <-chan time.Time
	var latestFollowupDue time.Time
	var passStartedAt time.Time
	var followupPending bool
	armLossFollowup := func(delay time.Duration) {
		stopCgroupRecoveryTimer(lossFollowup)
		lossFollowup.Reset(max(delay, time.Millisecond))
		lossFollowupC = lossFollowup.C
	}
	scheduleLossFollowup := func() {
		due := time.Now().Add(timing.maxIdle)
		armDue := due
		if !latestFollowupDue.IsZero() && latestFollowupDue.Before(armDue) &&
			(passStartedAt.IsZero() || latestFollowupDue.After(passStartedAt)) {
			armDue = latestFollowupDue
		}
		if due.After(latestFollowupDue) {
			latestFollowupDue = due
		}
		if lossFollowupC == nil {
			armLossFollowup(time.Until(armDue))
		}
	}
	resetContinuation := func(delay time.Duration) {
		stopCgroupRecoveryTimer(continuation)
		continuation.Reset(delay)
		continuationC = continuation.C
	}
	clearContinuation := func() {
		stopCgroupRecoveryTimer(continuation)
		continuationC = nil
	}
	runSweep := func(reason string) {
		if passStartedAt.IsZero() {
			passStartedAt = time.Now()
		}
		result, err := backend.SweepUDPRecovery(timing.maxIdle, cgroupRecoverySweepBudget)
		if err != nil {
			if !backend.IsClosed() {
				i.logger.Debug("sweep cgroup eBPF UDP recovery after ", reason, ": ", err)
				// A notification was already lost, so a transient map error
				// cannot return us to the healthy event-only state. Retry with
				// bounded backoff until one complete scan restores confidence.
				resetContinuation(timing.fallbackInterval)
			} else {
				clearContinuation()
				passStartedAt = time.Time{}
				latestFollowupDue = time.Time{}
				followupPending = false
				stopCgroupRecoveryTimer(lossFollowup)
				lossFollowupC = nil
			}
			return
		}
		if !result.Complete {
			resetContinuation(timing.continuation)
			return
		}
		clearContinuation()
		completedPassAt := passStartedAt
		passStartedAt = time.Time{}
		if !latestFollowupDue.IsZero() && latestFollowupDue.After(completedPassAt) {
			if followupPending {
				followupPending = false
				armLossFollowup(time.Millisecond)
			} else if lossFollowupC == nil {
				armLossFollowup(time.Until(latestFollowupDue))
			}
			return
		}
		followupPending = false
		latestFollowupDue = time.Time{}
		stopCgroupRecoveryTimer(lossFollowup)
		lossFollowupC = nil
	}
	// Start from zero so kernel ring-buffer drops incurred between Attach() and
	// this goroutine's first poll still trigger recovery on the first watchdog tick.
	var lastKernelDrops uint64
	resetTimer := func() {
		if len(deadlines) == 0 {
			timerC = nil
			return
		}
		stopCgroupRecoveryTimer(timer)
		delay := time.Until(deadlines[0].deadline)
		if delay < 0 {
			delay = 0
		}
		timer.Reset(delay)
		timerC = timer.C
	}
	for {
		select {
		case <-ctx.Done():
			return
		case event := <-events:
			heap.Push(&deadlines, cgroupRecoveryDeadline{event: event, deadline: time.Now().Add(timing.maxIdle)})
			resetTimer()
		case <-sweepWake:
			scheduleLossFollowup()
			runSweep("userspace release queue overflow")
		case <-expiryWake:
			scheduleLossFollowup()
		case <-continuationC:
			continuationC = nil
			runSweep("partial scan continuation")
		case <-lossFollowupC:
			lossFollowupC = nil
			if passStartedAt.IsZero() {
				runSweep("cgroup UDP recovery deadline")
			} else {
				followupPending = true
			}
		case <-readerError:
			if fallbackTicker == nil {
				fallbackTicker = time.NewTicker(timing.fallbackInterval)
				fallbackC = fallbackTicker.C
			}
			runSweep("release event reader failure")
		case <-fallbackC:
			runSweep("release event reader fallback")
		case <-timerC:
			now := time.Now()
			for len(deadlines) > 0 && !deadlines[0].deadline.After(now) {
				entry := heap.Pop(&deadlines).(cgroupRecoveryDeadline)
				_, err := backend.DeleteUDPRecovery(entry.event.Listener, entry.event.SocketCookie, entry.event.NetworkGeneration, entry.event.ReleasedAtNS)
				if err != nil && !backend.IsClosed() {
					i.logger.Debug("delete expired cgroup eBPF UDP recovery entry: ", err)
					resetContinuation(timing.continuation)
				}
			}
			resetTimer()
		case <-watchdog.C:
			// A lost kernel event cannot wake userspace, but its per-CPU drop
			// counter can. Healthy ring-buffer operation performs no map scan.
			drops, err := backend.UDPReleaseNotificationDrops()
			if err != nil {
				if !backend.IsClosed() {
					i.logger.Debug("read cgroup eBPF UDP release drop counter: ", err)
				}
				continue
			}
			if drops != lastKernelDrops {
				lastKernelDrops = drops
				scheduleLossFollowup()
				runSweep("kernel release notification loss")
			}
		}
	}
}

func (i *Inbound) runCgroupRecoveryFallback(ctx context.Context, backend cgroupRecoveryBackend, timing cgroupRecoveryTiming) {
	timer := time.NewTimer(timing.fallbackInterval)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		result, err := backend.SweepUDPRecovery(timing.maxIdle, cgroupRecoverySweepBudget)
		if err != nil && !backend.IsClosed() {
			i.logger.Debug("sweep stale cgroup eBPF UDP recovery entries: ", err)
		}
		delay := timing.fallbackInterval
		if err == nil && !result.Complete {
			delay = timing.continuation
		}
		timer.Reset(delay)
	}
}

func stopCgroupRecoveryTimer(timer *time.Timer) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
}
