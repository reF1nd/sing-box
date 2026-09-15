//go:build with_ebpf && (linux || android)

package ebpf

import "sync/atomic"

// ebpfCounters contains cumulative process-side diagnostics. Counters are
// incremented only where the event is already observed and never per packet
// solely for reporting.
type ebpfCounters struct {
	// assignmentLookupFailures counts redirected packets whose assignment
	// could not be recovered in userspace.
	assignmentLookupFailures atomic.Uint64
	// sharedReconcileFailures counts failed packet-rewrite reconcile passes.
	sharedReconcileFailures atomic.Uint64
	// Recovery counts cover TC, packet-rewrite, and bypass-rule-set components.
	recoveryAttempts  atomic.Uint64
	recoverySuccesses atomic.Uint64
	recoveryFailures  atomic.Uint64
}

// EBPFCounters merges process-side atomics with native map counters. FakeIP
// counters are summed across every backend hosting the responder.
type EBPFCounters struct {
	AssignmentLookupFailures uint64 `json:"assignment_lookup_failures"`
	// Native packet-rewrite counters are zero when that backend is disabled.
	TokenReservationFailures uint64 `json:"token_reservation_failures"`
	RewriteFailures          uint64 `json:"rewrite_failures"`
	SharedReconcileFailures  uint64 `json:"shared_reconcile_failures"`
	RecoveryAttempts         uint64 `json:"recovery_attempts"`
	RecoverySuccesses        uint64 `json:"recovery_successes"`
	RecoveryFailures         uint64 `json:"recovery_failures"`
	// PassThrough counts only echo requests examined and declined.
	FakeIPICMPReplies             uint64 `json:"fakeip_icmp_replies"`
	FakeIPICMPPassThrough         uint64 `json:"fakeip_icmp_pass_through"`
	FakeIPICMPRewriteFailureDrops uint64 `json:"fakeip_icmp_rewrite_failure_drops"`
}

func (c *ebpfCounters) snapshot() EBPFCounters {
	return EBPFCounters{
		AssignmentLookupFailures: c.assignmentLookupFailures.Load(),
		SharedReconcileFailures:  c.sharedReconcileFailures.Load(),
		RecoveryAttempts:         c.recoveryAttempts.Load(),
		RecoverySuccesses:        c.recoverySuccesses.Load(),
		RecoveryFailures:         c.recoveryFailures.Load(),
	}
}
