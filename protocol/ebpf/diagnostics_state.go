//go:build with_ebpf && (linux || android)

package ebpf

import (
	"sync"
	"time"
)

// tcOutcomeHistory is the small amount of extra bookkeeping Diagnostics
// needs that nothing else in this package already tracks: the last outcome
// runTCInterfaceUpdateLoop's update step reported, when a failing component
// most recently cleared, and the loop's own current retry schedule.
type tcOutcomeHistory struct {
	access         sync.Mutex
	haveOutcome    bool
	lastOutcome    tcUpdateOutcome
	lastOutcomeAt  time.Time
	lastRecoveryAt time.Time
	// nextRetryAt is the zero time when the retry timer is currently
	// disarmed (nothing outstanding across any of the three components).
	nextRetryAt       time.Time
	lastHealthCheckAt time.Time
	lastHealthHealthy bool
	lastReconcileAt   time.Time
}

func (i *Inbound) recordTCHealthCheck(healthy bool) {
	i.diagnostics.access.Lock()
	i.diagnostics.lastHealthCheckAt = time.Now()
	i.diagnostics.lastHealthHealthy = healthy
	i.diagnostics.access.Unlock()
}

func (i *Inbound) recordTCReconcile() {
	i.diagnostics.access.Lock()
	i.diagnostics.lastReconcileAt = time.Now()
	i.diagnostics.access.Unlock()
}

// recordNextRetryDeadline is runTCInterfaceUpdates' onScheduleChange hook:
// called every time runTCInterfaceUpdateLoop arms or disarms its single
// physical timer, so Diagnostics reports exactly the schedule the loop is
// actually running on, not a value recomputed separately from state this
// function does not otherwise expose.
func (i *Inbound) recordNextRetryDeadline(deadline time.Time) {
	i.diagnostics.access.Lock()
	i.diagnostics.nextRetryAt = deadline
	i.diagnostics.access.Unlock()
}

// recordTCUpdateOutcome is runTCInterfaceUpdates' hook: called with every
// outcome the update step reports, whether or not anything changed, so
// Diagnostics always reflects the most recent round. It also drives
// ebpfCounters' recovery attempt/success/failure counts, across all three
// of tcUpdateOutcome's components: one attempt per round in which any
// component reported Recoverable, one success per component transition from
// Recoverable to Settled, one failure per component transition to
// Unrecoverable.
func (i *Inbound) recordTCUpdateOutcome(outcome tcUpdateOutcome) {
	now := time.Now()
	i.diagnostics.access.Lock()
	defer i.diagnostics.access.Unlock()

	components := [...]tcSharedRewriteOutcome{outcome.sharedRewrite, outcome.general, outcome.bypassRuleSet}
	var previousComponents [3]tcSharedRewriteOutcome
	if i.diagnostics.haveOutcome {
		previousComponents = [3]tcSharedRewriteOutcome{
			i.diagnostics.lastOutcome.sharedRewrite,
			i.diagnostics.lastOutcome.general,
			i.diagnostics.lastOutcome.bypassRuleSet,
		}
	}
	recoveredThisRound := false
	attemptedThisRound := false
	stored := components
	for index, current := range components {
		if current == tcSharedRewriteRecoverable {
			attemptedThisRound = true
		}
		if i.diagnostics.haveOutcome {
			switch {
			case previousComponents[index] == tcSharedRewriteRecoverable && current == tcSharedRewriteSettled:
				i.counters.recoverySuccesses.Add(1)
				recoveredThisRound = true
			case previousComponents[index] != tcSharedRewriteUnrecoverable && current == tcSharedRewriteUnrecoverable:
				i.counters.recoveryFailures.Add(1)
			}
			// tcSharedRewriteUnknown means this round never actually
			// evaluated this component (updateTCInterfaces can return
			// before reaching a later component's own check -- see its own
			// doc comment), not that the component has settled. Storing it
			// as-is would silently erase whatever the last round that DID
			// evaluate this component actually found, including a still
			// -unresolved Unrecoverable -- exactly what Diagnostics' state
			// derivation needs to keep reporting needs_attention for.
			if current == tcSharedRewriteUnknown {
				stored[index] = previousComponents[index]
			}
		}
	}
	if attemptedThisRound {
		i.counters.recoveryAttempts.Add(1)
	}
	if recoveredThisRound {
		i.diagnostics.lastRecoveryAt = now
	}
	i.diagnostics.lastOutcome = tcUpdateOutcome{
		sharedRewrite: stored[0],
		general:       stored[1],
		bypassRuleSet: stored[2],
	}
	i.diagnostics.lastOutcomeAt = now
	i.diagnostics.haveOutcome = true
}
