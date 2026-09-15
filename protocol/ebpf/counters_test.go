//go:build with_ebpf && (linux || android)

package ebpf

import "testing"

// TestRecordTCUpdateOutcomeCountsRecoveryAttempts proves a round in which
// any component reports Recoverable counts as one attempt, whether or not
// any other component is settled at the same time.
func TestRecordTCUpdateOutcomeCountsRecoveryAttempts(t *testing.T) {
	inbound := &Inbound{}
	inbound.recordTCUpdateOutcome(tcUpdateOutcome{
		sharedRewrite: tcSharedRewriteSettled,
		general:       tcSharedRewriteRecoverable,
		bypassRuleSet: tcSharedRewriteSettled,
	})
	if attempts := inbound.counters.recoveryAttempts.Load(); attempts != 1 {
		t.Fatalf("recoveryAttempts = %d, want 1", attempts)
	}
	inbound.recordTCUpdateOutcome(tcUpdateOutcome{
		sharedRewrite: tcSharedRewriteSettled,
		general:       tcSharedRewriteSettled,
		bypassRuleSet: tcSharedRewriteSettled,
	})
	if attempts := inbound.counters.recoveryAttempts.Load(); attempts != 1 {
		t.Fatalf("recoveryAttempts = %d, want still 1 after an all-settled round", attempts)
	}
}

// TestRecordTCUpdateOutcomeCountsRecoverySuccessPerComponent proves each
// component transitioning from Recoverable to Settled counts its own
// success -- two components recovering in the same round count as two.
func TestRecordTCUpdateOutcomeCountsRecoverySuccessPerComponent(t *testing.T) {
	inbound := &Inbound{}
	inbound.recordTCUpdateOutcome(tcUpdateOutcome{
		sharedRewrite: tcSharedRewriteRecoverable,
		general:       tcSharedRewriteRecoverable,
		bypassRuleSet: tcSharedRewriteSettled,
	})
	if successes := inbound.counters.recoverySuccesses.Load(); successes != 0 {
		t.Fatalf("recoverySuccesses = %d, want 0 before anything has settled", successes)
	}
	inbound.recordTCUpdateOutcome(tcUpdateOutcome{
		sharedRewrite: tcSharedRewriteSettled,
		general:       tcSharedRewriteSettled,
		bypassRuleSet: tcSharedRewriteSettled,
	})
	if successes := inbound.counters.recoverySuccesses.Load(); successes != 2 {
		t.Fatalf("recoverySuccesses = %d, want 2 (both sharedRewrite and general settled)", successes)
	}
}

// TestRecordTCUpdateOutcomeCountsRecoveryFailureOnUnrecoverable proves a
// transition to Unrecoverable counts as a failure exactly once, not on
// every subsequent round it stays Unrecoverable.
func TestRecordTCUpdateOutcomeCountsRecoveryFailureOnUnrecoverable(t *testing.T) {
	inbound := &Inbound{}
	inbound.recordTCUpdateOutcome(tcUpdateOutcome{
		sharedRewrite: tcSharedRewriteSettled,
		general:       tcSharedRewriteRecoverable,
		bypassRuleSet: tcSharedRewriteSettled,
	})
	inbound.recordTCUpdateOutcome(tcUpdateOutcome{
		sharedRewrite: tcSharedRewriteSettled,
		general:       tcSharedRewriteUnrecoverable,
		bypassRuleSet: tcSharedRewriteSettled,
	})
	if failures := inbound.counters.recoveryFailures.Load(); failures != 1 {
		t.Fatalf("recoveryFailures = %d, want 1", failures)
	}
	inbound.recordTCUpdateOutcome(tcUpdateOutcome{
		sharedRewrite: tcSharedRewriteSettled,
		general:       tcSharedRewriteUnrecoverable,
		bypassRuleSet: tcSharedRewriteSettled,
	})
	if failures := inbound.counters.recoveryFailures.Load(); failures != 1 {
		t.Fatalf("recoveryFailures = %d, want still 1 while it stays Unrecoverable", failures)
	}
}

// TestAssignmentLookupFailureCounterInDiagnostics proves the counter
// incremented at tc_connection.go's failure sites is what Diagnostics
// reports -- exercised directly here rather than through a real lookup,
// since the counter itself, not the lookup, is what this test is about.
func TestAssignmentLookupFailureCounterInDiagnostics(t *testing.T) {
	inbound := &Inbound{}
	inbound.counters.assignmentLookupFailures.Add(3)
	if got := inbound.Diagnostics().Counters.AssignmentLookupFailures; got != 3 {
		t.Fatalf("Counters.AssignmentLookupFailures = %d, want 3", got)
	}
}

// TestSharedReconcileFailureCounterInDiagnostics is the same proof for the
// shared packet-rewrite reconcile-failure counter.
func TestSharedReconcileFailureCounterInDiagnostics(t *testing.T) {
	inbound := &Inbound{}
	inbound.counters.sharedReconcileFailures.Add(2)
	if got := inbound.Diagnostics().Counters.SharedReconcileFailures; got != 2 {
		t.Fatalf("Counters.SharedReconcileFailures = %d, want 2", got)
	}
}
