//go:build with_ebpf && (linux || android)

package ebpf

import (
	"container/heap"
	"context"
	"time"

	commonEBPF "github.com/CHIZI-0618/sing-ebpf"
)

const (
	cgroupRecoveryMaxIdle     = 30 * time.Second
	cgroupRecoverySweepBudget = 1024
	cgroupRecoveryQueueSize   = 1024
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
	}
	go i.runCgroupRecoveryScheduler(ctx, backend, done)
}

func (i *Inbound) stopCgroupRecoveryScheduler() {
	i.cgroupRecoveryAccess.Lock()
	if i.cgroupRecoveryCancel == nil {
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
	i.cgroupRecoveryAccess.Unlock()
}

func (i *Inbound) enqueueCgroupRecoveryEvent(backend *commonEBPF.CgroupBackend, event commonEBPF.UDPReleaseEvent) {
	i.cgroupRecoveryAccess.Lock()
	queue := i.cgroupRecoveryEvents
	if queue != nil {
		select {
		case queue <- event:
			i.cgroupRecoveryAccess.Unlock()
			return
		default:
		}
	}
	i.cgroupRecoveryAccess.Unlock()
	// A full queue means the event stream is incomplete. Use one bounded
	// value-checked sweep immediately instead of waiting for LRU pressure.
	if _, err := backend.SweepUDPRecovery(cgroupRecoveryMaxIdle, cgroupRecoverySweepBudget); err != nil && !backend.IsClosed() {
		i.logger.Debug("sweep cgroup eBPF UDP recovery after release queue overflow: ", err)
	}
}

func (i *Inbound) runCgroupRecoveryScheduler(ctx context.Context, backend *commonEBPF.CgroupBackend, done chan<- struct{}) {
	defer close(done)
	i.cgroupRecoveryAccess.Lock()
	events := i.cgroupRecoveryEvents
	i.cgroupRecoveryAccess.Unlock()
	if events == nil {
		i.runCgroupRecoveryFallback(ctx, backend)
		return
	}
	deadlines := make(cgroupRecoveryDeadlineHeap, 0, cgroupRecoveryQueueSize)
	heap.Init(&deadlines)
	timer := time.NewTimer(time.Hour)
	stopCgroupRecoveryTimer(timer)
	defer timer.Stop()
	var timerC <-chan time.Time
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
			heap.Push(&deadlines, cgroupRecoveryDeadline{event: event, deadline: time.Now().Add(cgroupRecoveryMaxIdle)})
			resetTimer()
		case <-timerC:
			now := time.Now()
			for len(deadlines) > 0 && !deadlines[0].deadline.After(now) {
				entry := heap.Pop(&deadlines).(cgroupRecoveryDeadline)
				_, err := backend.DeleteUDPRecovery(entry.event.Listener, entry.event.SocketCookie, entry.event.NetworkGeneration, entry.event.ReleasedAtNS)
				if err != nil && !backend.IsClosed() {
					i.logger.Debug("delete expired cgroup eBPF UDP recovery entry: ", err)
				}
			}
			resetTimer()
		}
	}
}

func (i *Inbound) runCgroupRecoveryFallback(ctx context.Context, backend *commonEBPF.CgroupBackend) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		_, err := backend.SweepUDPRecovery(cgroupRecoveryMaxIdle, cgroupRecoverySweepBudget)
		if err != nil && !backend.IsClosed() {
			i.logger.Debug("sweep stale cgroup eBPF UDP recovery entries: ", err)
		}
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
