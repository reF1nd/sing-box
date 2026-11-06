//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"time"
)

const (
	tcRetryInitialDelay = 2 * time.Second
	tcRetryMaximumDelay = time.Minute
)

// tcDriftCheckInterval is the low-frequency health-check interval used while a
// TC or shared packet-rewrite data plane is active. Those attachments and their
// routing state can be removed without a network event. A healthy check stays
// read-only; detected drift falls through to full reconciliation. A pure
// cgroup data plane has no such TC state, so it keeps event-driven updates and
// retry timers but passes a disabled interval to the loop below.
var tcDriftCheckInterval = 10 * time.Minute

// tcSharedRewriteOutcome is what one named component of an interface update
// reported.
//
// A single update can name more than one outcome (see tcUpdateOutcome):
// tcSharedRewriteOutcome itself is not scoped to shared packet-rewrite
// specifically despite the name, which is kept only because runTCInterfaceUpdateLoop's
// existing tests, and shared_rewrite_dataplane.go's own retryOutcome, already
// name it and its four values throughout.
type tcSharedRewriteOutcome int

const (
	// tcSharedRewriteUnknown means the shared packet-rewrite step did not run,
	// because the update returned before reaching it. It says nothing about
	// whether a recovery is outstanding, so a pending retry is left alone rather
	// than cancelled.
	tcSharedRewriteUnknown tcSharedRewriteOutcome = iota
	// tcSharedRewriteSettled means there is nothing to recover: the step
	// succeeded, or there is no shared packet-rewrite data plane to run.
	tcSharedRewriteSettled
	tcSharedRewriteRecoverable
	// tcSharedRewriteUnrecoverable means the backend is closed or has to be
	// rebuilt, so repeating the attach cannot succeed.
	tcSharedRewriteUnrecoverable
)

// tcRetryComponent names one of tcUpdateOutcome's independently-backed-off
// fields, for logging and for indexing runTCInterfaceUpdateLoop's internal
// per-component state.
type tcRetryComponent int

const (
	tcRetryComponentSharedRewrite tcRetryComponent = iota
	tcRetryComponentGeneral
	tcRetryComponentBypassRuleSet
	tcRetryComponentCount
)

func (c tcRetryComponent) String() string {
	switch c {
	case tcRetryComponentSharedRewrite:
		return "shared packet-rewrite"
	case tcRetryComponentGeneral:
		return "TC attachment/infrastructure/host policy"
	case tcRetryComponentBypassRuleSet:
		return "bypass_rule_set"
	default:
		return "unknown"
	}
}

// tcUpdateOutcome is what one full interface-update pass reported, broken out
// per component so runTCInterfaceUpdateLoop can back each one off
// independently: one component settling must not cancel another's pending
// recovery, matching the same requirement shared packet-rewrite's own outcome
// already satisfied before general TC and bypass_rule_set failures were also
// covered by this scheduler.
//
//   - sharedRewrite: the shared packet-rewrite attach step specifically. The
//     adapter classifies the runtime's backend health into this scheduler's
//     recoverable/unrecoverable states.
//   - general: every other TC step in updateTCInterfaces -- inventory,
//     topology, infrastructure (routing/rules/delivery veth), the attachment
//     reconcile itself, and host address policy. These are combined into one
//     bucket rather than tracked individually: they already run as one
//     sequential pass sharing the same lock and largely the same recovery
//     path (a fresh reconcile), so splitting them further would track more
//     state without changing what actually gets retried or when.
//   - bypassRuleSet: refreshing the compiled bypass_rule_set policy, driven
//     normally by rule-set update callbacks rather than network events, which
//     is exactly the case this scheduler exists to also cover: a transient
//     failure with no later rule-set change to retry it.
type tcUpdateOutcome struct {
	sharedRewrite tcSharedRewriteOutcome
	general       tcSharedRewriteOutcome
	bypassRuleSet tcSharedRewriteOutcome
}

// tcRetryTimer is the slice of *time.Timer this loop needs, reduced to the two
// operations a round performs. A round makes at most one of them: an
// event-driven round that finds the shared step did not run makes none, because
// it must leave the deadline it did not observe exactly as it was. Arming hides
// the stop-and-drain a bare Reset would require, which keeps a signal from a
// previous delay out of the next one. Tests substitute it to drive the backoff
// without waiting on real time.
type tcRetryTimer interface {
	Arm(delay time.Duration)
	Disarm()
	Expired() <-chan time.Time
}

type tcRealRetryTimer struct {
	timer *time.Timer
}

// newTCRetryTimer returns a timer that is not running, so the loop can hold one
// for its whole life and arm it only when a recovery is outstanding.
func newTCRetryTimer() tcRetryTimer {
	timer := time.NewTimer(time.Hour)
	if !timer.Stop() {
		<-timer.C
	}
	return &tcRealRetryTimer{timer: timer}
}

func (t *tcRealRetryTimer) Arm(delay time.Duration) {
	t.drain()
	t.timer.Reset(delay)
}

func (t *tcRealRetryTimer) Disarm() {
	t.drain()
}

func (t *tcRealRetryTimer) drain() {
	if !t.timer.Stop() {
		select {
		case <-t.timer.C:
		default:
		}
	}
}

func (t *tcRealRetryTimer) Expired() <-chan time.Time { return t.timer.C }

var tcRetryTimerFactory = newTCRetryTimer

func (i *Inbound) runTCInterfaceUpdates(ctx context.Context, updates <-chan struct{}) {
	runTCInterfaceUpdateLoopWithHealth(ctx, updates, i.interfaceDriftCheckInterval(), i.tcInterfaceHealthCheck, func(ctx context.Context) tcUpdateOutcome {
		outcome := i.updateTCInterfaces(ctx)
		i.recordTCUpdateOutcome(outcome)
		return outcome
	}, i.recordNextRetryDeadline)
}

func (i *Inbound) interfaceDriftCheckInterval() time.Duration {
	i.tcDataPlaneAccess.RLock()
	hasTCDataPlane := i.tcDataPlane != nil
	i.tcDataPlaneAccess.RUnlock()
	if hasTCDataPlane || i.sharedRewriteInstance() != nil {
		return tcDriftCheckInterval
	}
	return 0
}

// tcRetryState is one component's independently-tracked backoff: delay is
// the duration it last waited (0 means nothing pending), and deadline is the
// absolute time that delay was measured from -- computed once, from the same
// "now" snapshot used across a whole round, specifically so a component that
// becomes the single earliest one this round arms the real timer for exactly
// delay, with no wall-clock rounding from re-deriving it through time.Now()
// a second time.
type tcRetryState struct {
	delay    time.Duration
	deadline time.Time
}

// runTCInterfaceUpdateLoop drives interface updates from netlink
// notifications, from an optional low-frequency drift check,
// and, while any of update's three components has a recoverable failure
// outstanding, from that component's own backoff timer. A non-positive
// driftCheckInterval disables only the periodic health check; events and
// recovery timers remain active.
//
// Only one physical timer exists; it is armed for whichever component's
// deadline is soonest. A netlink notification or a failed health check still
// runs an update immediately, but neither resets any component's backoff: this
// data plane generates netlink events of its own while attaching and
// detaching, and an unrelated event on another interface arrives just as
// often, so treating any event as progress would keep restarting the delay
// and turn the backoff into a busy loop. A component's delay resets only
// after a round in which that component reported nothing left to recover.
// onScheduleChange, when non-nil, is called every time the loop's single
// physical timer is armed or disarmed, with the absolute time it is now
// armed for (or the zero time when disarmed) -- runTCInterfaceUpdates uses
// it to keep Diagnostics' "next retry time" in sync with the same schedule
// the timer itself is actually running on, rather than recomputing it
// separately from state this function does not otherwise expose.
func runTCInterfaceUpdateLoop(
	ctx context.Context,
	updates <-chan struct{},
	driftCheckInterval time.Duration,
	update func(context.Context) tcUpdateOutcome,
	onScheduleChange func(deadline time.Time),
) {
	runTCInterfaceUpdateLoopWithHealth(ctx, updates, driftCheckInterval, nil, update, onScheduleChange)
}

func runTCInterfaceUpdateLoopWithHealth(
	ctx context.Context,
	updates <-chan struct{},
	driftCheckInterval time.Duration,
	healthCheck func(context.Context) bool,
	update func(context.Context) tcUpdateOutcome,
	onScheduleChange func(deadline time.Time),
) {
	retryTimer := tcRetryTimerFactory()
	defer retryTimer.Disarm()
	var (
		driftCheck        *time.Ticker
		driftCheckChannel <-chan time.Time
	)
	if driftCheckInterval > 0 {
		driftCheck = time.NewTicker(driftCheckInterval)
		driftCheckChannel = driftCheck.C
		defer driftCheck.Stop()
	}
	var (
		retryChannel <-chan time.Time
		states       [tcRetryComponentCount]tcRetryState
	)
	for {
		// The timer's channel is only selected on while some component has a
		// recovery outstanding, so a disarmed timer cannot deliver a signal
		// from an earlier delay.
		triggeredByTimer := false
		triggeredByHealthCheck := false
		select {
		case <-ctx.Done():
			return
		case <-updates:
		case <-driftCheckChannel:
			triggeredByHealthCheck = true
		case <-retryChannel:
			triggeredByTimer = true
		}
		// A notification, the health check, and the retry timer can all be
		// ready together and select picks one at random. The three signals
		// are handled differently and neither of the other two is lost:
		// re-arming or disarming below drains a timer fire that was already
		// queued, since it belongs to a deadline this round has just
		// superseded, while a queued notification stays in its channel and
		// drives the next round, and the health check ticker keeps its own
		// schedule independently of anything below.
		if ctx.Err() != nil {
			return
		}
		if triggeredByHealthCheck && healthCheck != nil && healthCheck(ctx) {
			continue
		}
		now := time.Now()
		outcome := update(ctx)
		outcomes := [tcRetryComponentCount]tcSharedRewriteOutcome{
			tcRetryComponentSharedRewrite: outcome.sharedRewrite,
			tcRetryComponentGeneral:       outcome.general,
			tcRetryComponentBypassRuleSet: outcome.bypassRuleSet,
		}
		changed := false
		for component, componentOutcome := range outcomes {
			switch componentOutcome {
			case tcSharedRewriteRecoverable:
				// Advance on every failed round, including one an event or the
				// health check triggered, so a stream of those cannot hold this
				// component's delay down.
				states[component].delay = nextTCRetryDelay(states[component].delay)
				states[component].deadline = now.Add(states[component].delay)
				changed = true
			case tcSharedRewriteUnknown:
				// This component's step did not run, so it says nothing about an
				// outstanding recovery for that component specifically. Only
				// re-arm when the timer is what woke this round: some
				// component's deadline has passed, and if it was this one its
				// retry would otherwise be dropped. An event- or health-check-
				// driven round leaves this component's existing deadline alone,
				// or a stream of those returning early would postpone its retry
				// indefinitely.
				if triggeredByTimer && states[component].delay > 0 {
					states[component].deadline = now.Add(states[component].delay)
					changed = true
				}
			default: // settled or unrecoverable
				// sharedRewrite's own settled/unrecoverable handling has
				// always unconditionally touched the timer, proven by tests
				// predating general and bypassRuleSet joining this scheduler,
				// including a first-ever round with nothing previously
				// tracked. general and bypassRuleSet keep the more efficient
				// transition-gated behavior: since a component with nothing
				// to recover is by far the common case for both, an
				// unconditional touch would mean every single round pays for
				// a real timer access, for two components most rounds never
				// have anything to say about.
				if tcRetryComponent(component) == tcRetryComponentSharedRewrite || !states[component].deadline.IsZero() {
					changed = true
				}
				states[component].delay = 0
				states[component].deadline = time.Time{}
			}
		}
		if !changed {
			continue
		}
		earliest := -1
		for component := range states {
			if states[component].deadline.IsZero() {
				continue
			}
			if earliest == -1 || states[component].deadline.Before(states[earliest].deadline) {
				earliest = component
			}
		}
		if earliest == -1 {
			retryTimer.Disarm()
			retryChannel = nil
			if onScheduleChange != nil {
				onScheduleChange(time.Time{})
			}
			continue
		}
		delay := states[earliest].deadline.Sub(now)
		if delay < 0 {
			delay = 0
		}
		retryTimer.Arm(delay)
		retryChannel = retryTimer.Expired()
		if onScheduleChange != nil {
			onScheduleChange(states[earliest].deadline)
		}
	}
}
