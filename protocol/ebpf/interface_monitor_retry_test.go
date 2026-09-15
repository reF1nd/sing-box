//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"sync"
	"testing"
	"time"
)

// testRetryTimerAction is one arm or disarm the loop performed. The loop makes
// exactly one of these per round, which is what lets a test wait for a round's
// bookkeeping to finish instead of sleeping.
type testRetryTimerAction struct {
	armed bool
	delay time.Duration
}

// testRetryTimer stands in for the loop's timer. Every field is guarded because
// the loop goroutine writes them while the test goroutine reads them, and the
// actions channel is the only synchronisation the test relies on.
type testRetryTimer struct {
	access  sync.Mutex
	expired chan time.Time
	armed   bool
	delays  []time.Duration
	actions chan testRetryTimerAction
}

func (t *testRetryTimer) Arm(delay time.Duration) {
	t.access.Lock()
	t.drainLocked()
	t.armed = true
	t.delays = append(t.delays, delay)
	t.access.Unlock()
	t.actions <- testRetryTimerAction{armed: true, delay: delay}
}

func (t *testRetryTimer) Disarm() {
	t.access.Lock()
	t.drainLocked()
	t.armed = false
	t.access.Unlock()
	t.actions <- testRetryTimerAction{}
}

// drainLocked discards a fire that was queued but not consumed, mirroring what
// the real timer does when it is stopped after expiring.
func (t *testRetryTimer) drainLocked() {
	select {
	case <-t.expired:
	default:
	}
}

func (t *testRetryTimer) Expired() <-chan time.Time { return t.expired }

// fire delivers a tick the way an expired timer would. It is only safe to call
// while the timer is armed and the loop is waiting, which the harness enforces
// by draining the action of the round that armed it first.
func (t *testRetryTimer) fire(t2 *testing.T) {
	t2.Helper()
	t.access.Lock()
	armed := t.armed
	t.access.Unlock()
	if !armed {
		t2.Fatal("the retry timer is not armed; a fire here would be dropped")
	}
	select {
	case t.expired <- time.Now():
	case <-time.After(2 * time.Second):
		t2.Fatal("the loop is not waiting on the retry timer")
	}
}

func (t *testRetryTimer) snapshot() ([]time.Duration, bool) {
	t.access.Lock()
	defer t.access.Unlock()
	return append([]time.Duration(nil), t.delays...), t.armed
}

// retryLoopHarness runs the update loop and steps it one round at a time.
type retryLoopHarness struct {
	updates  chan struct{}
	timer    *testRetryTimer
	cancel   context.CancelFunc
	finished chan struct{}
	// update is what each round runs. Tests replace it before triggering a round.
	update func() tcSharedRewriteOutcome
	// ran receives one value per completed update, before the loop touches the
	// timer, so a test can tell an update happened without reading timer state.
	ran chan struct{}
}

func newRetryLoopHarness(t *testing.T) *retryLoopHarness {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	timer := &testRetryTimer{
		expired: make(chan time.Time, 1),
		actions: make(chan testRetryTimerAction, 64),
	}
	previous := tcRetryTimerFactory
	tcRetryTimerFactory = func() tcRetryTimer { return timer }
	t.Cleanup(func() { tcRetryTimerFactory = previous })

	harness := &retryLoopHarness{
		updates:  make(chan struct{}, 1),
		timer:    timer,
		cancel:   cancel,
		finished: make(chan struct{}),
		ran:      make(chan struct{}, 64),
		update:   func() tcSharedRewriteOutcome { return tcSharedRewriteSettled },
	}
	go func() {
		defer close(harness.finished)
		// This harness and every existing test built on it only ever cares
		// about the sharedRewrite component; general and bypassRuleSet are
		// pinned to Settled so they never affect the arm/disarm sequence
		// these tests assert on. interface_monitor_retry_components_test.go
		// covers those two components' own independence directly.
		runTCInterfaceUpdateLoop(ctx, harness.updates, func(context.Context) tcUpdateOutcome {
			outcome := harness.update()
			harness.ran <- struct{}{}
			return tcUpdateOutcome{sharedRewrite: outcome, general: tcSharedRewriteSettled, bypassRuleSet: tcSharedRewriteSettled}
		}, nil)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-harness.finished:
		case <-time.After(2 * time.Second):
			t.Error("update loop did not exit after cancellation")
		}
	})
	return harness
}

// round runs one update and returns after the loop has finished arming or
// disarming, so the returned action and any later snapshot are ordered after the
// loop's own writes.
func (h *retryLoopHarness) round(t *testing.T, trigger func(), outcome tcSharedRewriteOutcome) testRetryTimerAction {
	t.Helper()
	return h.roundFunc(t, trigger, func() tcSharedRewriteOutcome { return outcome })
}

func (h *retryLoopHarness) roundFunc(
	t *testing.T,
	trigger func(),
	update func() tcSharedRewriteOutcome,
) testRetryTimerAction {
	t.Helper()
	h.update = update
	trigger()
	select {
	case <-h.ran:
	case <-time.After(2 * time.Second):
		t.Fatal("update did not run")
	}
	select {
	case action := <-h.timer.actions:
		return action
	case <-time.After(2 * time.Second):
		t.Fatal("the loop did not arm or disarm after the update")
	}
	return testRetryTimerAction{}
}

func (h *retryLoopHarness) notify() { h.updates <- struct{}{} }

func (h *retryLoopHarness) fire(t *testing.T) func() {
	return func() { h.timer.fire(t) }
}

// expectNoAction asserts the loop performed no further timer bookkeeping, which
// is how a round that must leave an existing deadline alone is verified.
func (h *retryLoopHarness) expectNoAction(t *testing.T) {
	t.Helper()
	select {
	case action := <-h.timer.actions:
		t.Fatalf("unexpected timer action: %+v", action)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestNextTCRetryDelay(t *testing.T) {
	for _, testCase := range []struct {
		current time.Duration
		next    time.Duration
	}{
		{current: 0, next: 2 * time.Second},
		{current: 2 * time.Second, next: 4 * time.Second},
		{current: 4 * time.Second, next: 8 * time.Second},
		{current: 32 * time.Second, next: time.Minute},
		{current: time.Minute, next: time.Minute},
	} {
		if got := nextTCRetryDelay(testCase.current); got != testCase.next {
			t.Fatalf("nextTCRetryDelay(%s) = %s, want %s", testCase.current, got, testCase.next)
		}
	}
}

func TestRetryLoopArmsAndDisarms(t *testing.T) {
	harness := newRetryLoopHarness(t)

	action := harness.round(t, harness.notify, tcSharedRewriteRecoverable)
	if !action.armed || action.delay != tcRetryInitialDelay {
		t.Fatalf("action = %+v, want armed at %s", action, tcRetryInitialDelay)
	}

	action = harness.round(t, harness.fire(t), tcSharedRewriteSettled)
	if action.armed {
		t.Fatalf("action = %+v, want disarmed after recovery", action)
	}

	// A later failure starts the backoff over.
	action = harness.round(t, harness.notify, tcSharedRewriteRecoverable)
	if !action.armed || action.delay != tcRetryInitialDelay {
		t.Fatalf("action = %+v, want the backoff reset after recovery", action)
	}
}

func TestRetryLoopBacksOffToCap(t *testing.T) {
	harness := newRetryLoopHarness(t)

	harness.round(t, harness.notify, tcSharedRewriteRecoverable)
	for range 8 {
		harness.round(t, harness.fire(t), tcSharedRewriteRecoverable)
	}

	delays, armed := harness.timer.snapshot()
	want := []time.Duration{
		2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second,
		32 * time.Second, time.Minute, time.Minute, time.Minute, time.Minute,
	}
	if len(delays) != len(want) {
		t.Fatalf("armed delays = %v, want %v", delays, want)
	}
	for index, delay := range want {
		if delays[index] != delay {
			t.Fatalf("armed delays = %v, want %v", delays, want)
		}
	}
	if !armed {
		t.Fatal("the retry timer is not armed while a recovery is outstanding")
	}
}

func TestRetryLoopEventDoesNotResetBackoff(t *testing.T) {
	harness := newRetryLoopHarness(t)

	harness.round(t, harness.notify, tcSharedRewriteRecoverable)
	harness.round(t, harness.fire(t), tcSharedRewriteRecoverable)
	// An event arrives mid-backoff and the attach still fails.
	action := harness.round(t, harness.notify, tcSharedRewriteRecoverable)
	if action.delay != 8*time.Second {
		t.Fatalf("re-armed at %s, want 8s: an event must not shorten the delay", action.delay)
	}
}

// TestRetryLoopEventWithUnknownKeepsDeadline is the case an event-driven early
// return would otherwise postpone forever: a recovery is pending at some delay,
// and repeated events return before the shared step runs. The existing deadline
// has to survive untouched.
func TestRetryLoopEventWithUnknownKeepsDeadline(t *testing.T) {
	harness := newRetryLoopHarness(t)

	harness.round(t, harness.notify, tcSharedRewriteRecoverable)
	harness.round(t, harness.fire(t), tcSharedRewriteRecoverable)
	delaysBefore, _ := harness.timer.snapshot()

	// Three events in a row that never reach the shared step.
	for range 3 {
		harness.update = func() tcSharedRewriteOutcome { return tcSharedRewriteUnknown }
		harness.notify()
		select {
		case <-harness.ran:
		case <-time.After(2 * time.Second):
			t.Fatal("update did not run")
		}
		harness.expectNoAction(t)
	}

	delaysAfter, armed := harness.timer.snapshot()
	if len(delaysAfter) != len(delaysBefore) {
		t.Fatalf("armed delays = %v, want the pending deadline untouched (%v)", delaysAfter, delaysBefore)
	}
	if !armed {
		t.Fatal("the pending retry was dropped by an event-driven early return")
	}

	// The pending deadline still arrives and still drives a retry.
	action := harness.round(t, harness.fire(t), tcSharedRewriteRecoverable)
	if action.delay != 8*time.Second {
		t.Fatalf("re-armed at %s, want the backoff to continue at 8s", action.delay)
	}
}

// TestRetryLoopTimerWithUnknownReschedules covers the other trigger: the
// deadline passed and the step did not run, so the retry has to be scheduled
// again at the same delay rather than dropped.
func TestRetryLoopTimerWithUnknownReschedules(t *testing.T) {
	harness := newRetryLoopHarness(t)

	harness.round(t, harness.notify, tcSharedRewriteRecoverable)
	harness.round(t, harness.fire(t), tcSharedRewriteRecoverable)

	action := harness.round(t, harness.fire(t), tcSharedRewriteUnknown)
	if !action.armed || action.delay != 4*time.Second {
		t.Fatalf("action = %+v, want re-armed at the delay it had reached (4s)", action)
	}
}

func TestRetryLoopIgnoresUnknownWithNothingPending(t *testing.T) {
	harness := newRetryLoopHarness(t)

	harness.update = func() tcSharedRewriteOutcome { return tcSharedRewriteUnknown }
	harness.notify()
	select {
	case <-harness.ran:
	case <-time.After(2 * time.Second):
		t.Fatal("update did not run")
	}
	harness.expectNoAction(t)
	if _, armed := harness.timer.snapshot(); armed {
		t.Fatal("a timer was armed with no recovery outstanding")
	}
}

func TestRetryLoopStopsWhenUnrecoverable(t *testing.T) {
	harness := newRetryLoopHarness(t)

	harness.round(t, harness.notify, tcSharedRewriteRecoverable)
	action := harness.round(t, harness.fire(t), tcSharedRewriteUnrecoverable)
	if action.armed {
		t.Fatalf("action = %+v, want disarmed after an unrecoverable failure", action)
	}
	if _, armed := harness.timer.snapshot(); armed {
		t.Fatal("the retry timer is still armed after an unrecoverable failure")
	}
}

func TestRetryLoopStopsWhenTargetSettles(t *testing.T) {
	harness := newRetryLoopHarness(t)

	harness.round(t, harness.notify, tcSharedRewriteRecoverable)
	action := harness.round(t, harness.fire(t), tcSharedRewriteSettled)
	if action.armed {
		t.Fatalf("action = %+v, want disarmed once the target settled", action)
	}
}

// blockingUpdate returns an update callback that reports it has started and
// waits to be released, so a test can inject a signal while the loop is inside
// the update and construct an interleaving instead of hoping select picks a
// particular case.
func blockingUpdate(
	entered chan<- struct{},
	release <-chan struct{},
	outcome tcSharedRewriteOutcome,
) func() tcSharedRewriteOutcome {
	return func() tcSharedRewriteOutcome {
		entered <- struct{}{}
		<-release
		return outcome
	}
}

// TestRetryLoopDropsTickThatArrivesDuringEventRound covers a deadline expiring
// while an event-driven round is already running. That round supersedes the
// deadline, so the tick has to be discarded rather than driving a second round.
func TestRetryLoopDropsTickThatArrivesDuringEventRound(t *testing.T) {
	harness := newRetryLoopHarness(t)
	harness.round(t, harness.notify, tcSharedRewriteRecoverable)

	entered := make(chan struct{})
	release := make(chan struct{})
	// Fix the callback before triggering, so the loop cannot pick up a previous
	// one.
	harness.update = blockingUpdate(entered, release, tcSharedRewriteSettled)
	harness.notify()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("the event-driven update did not start")
	}

	// The deadline expires while that round is still inside the update.
	harness.timer.expired <- time.Now()
	close(release)
	select {
	case <-harness.ran:
	case <-time.After(2 * time.Second):
		t.Fatal("the event-driven update did not finish")
	}
	select {
	case action := <-harness.timer.actions:
		if action.armed {
			t.Fatalf("action = %+v, want disarmed", action)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the loop did not disarm")
	}

	// The superseded tick must not drive anything further.
	select {
	case <-harness.ran:
		t.Fatal("the discarded tick drove another round")
	case <-time.After(200 * time.Millisecond):
	}
	if queued := len(harness.timer.expired); queued != 0 {
		t.Fatalf("%d stale ticks are still queued", queued)
	}
	if _, armed := harness.timer.snapshot(); armed {
		t.Fatal("the timer is armed after the target settled")
	}
}

// TestRetryLoopHandlesEventQueuedDuringTimerRound is the other order: the timer
// round runs first and a real notification arrives while it is running. That
// notification is not superseded by anything, so it still has to drive a round.
func TestRetryLoopHandlesEventQueuedDuringTimerRound(t *testing.T) {
	harness := newRetryLoopHarness(t)
	harness.round(t, harness.notify, tcSharedRewriteRecoverable)

	entered := make(chan struct{})
	release := make(chan struct{})
	harness.update = blockingUpdate(entered, release, tcSharedRewriteRecoverable)
	harness.timer.fire(t)
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("the timer-driven update did not start")
	}

	// A genuine notification arrives while the timer round is running.
	harness.notify()
	// The next round is the queued notification; it must run.
	secondEntered := make(chan struct{}, 1)
	secondRelease := make(chan struct{})
	harness.update = blockingUpdate(secondEntered, secondRelease, tcSharedRewriteSettled)
	close(release)
	select {
	case <-harness.ran:
	case <-time.After(2 * time.Second):
		t.Fatal("the timer-driven update did not finish")
	}
	select {
	case action := <-harness.timer.actions:
		if !action.armed || action.delay != 2*tcRetryInitialDelay {
			t.Fatalf("action = %+v, want the backoff advanced to %s", action, 2*tcRetryInitialDelay)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the loop did not re-arm after the timer round")
	}
	select {
	case <-secondEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("the notification queued during the timer round was dropped")
	}
	close(secondRelease)
	select {
	case <-harness.ran:
	case <-time.After(2 * time.Second):
		t.Fatal("the notification-driven update did not finish")
	}
	select {
	case action := <-harness.timer.actions:
		if action.armed {
			t.Fatalf("action = %+v, want disarmed", action)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the loop did not disarm after the notification round")
	}
}

func TestRetryLoopExitsOnCancel(t *testing.T) {
	harness := newRetryLoopHarness(t)

	harness.round(t, harness.notify, tcSharedRewriteRecoverable)
	harness.cancel()
	select {
	case <-harness.finished:
	case <-time.After(2 * time.Second):
		t.Fatal("the loop did not exit after cancellation")
	}
	select {
	case action := <-harness.timer.actions:
		if action.armed {
			t.Fatalf("exit action = %+v, want the timer disarmed", action)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the timer was not disarmed on exit")
	}
}

func TestRetryLoopStopsBeforeUpdateWhenCancelled(t *testing.T) {
	harness := newRetryLoopHarness(t)

	harness.cancel()
	harness.notify()
	select {
	case <-harness.finished:
	case <-time.After(2 * time.Second):
		t.Fatal("the loop did not exit after cancellation")
	}
	select {
	case <-harness.ran:
		t.Fatal("an update ran after cancellation")
	default:
	}
}
