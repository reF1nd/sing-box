//go:build with_ebpf && (linux || android)

package ebpf

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"

	commonEBPF "github.com/CHIZI-0618/sing-ebpf"
)

// EBPFAttachmentDiagnostics describes one place this inbound is actually
// intercepting traffic right now: either a TC attachment on a network
// interface, or (Mechanism == "cgroup") the cgroup local data plane, which
// has no per-interface attachment of its own.
type EBPFAttachmentDiagnostics = commonEBPF.AttachmentInfo

// Runtime states EBPFDiagnostics.State reports. These summarize the fields
// below into the one value most operators actually want at a glance; the
// individual fields remain available for anything more specific.
const (
	// EBPFDiagnosticsStateNormal is every configured data plane attached and
	// no recovery outstanding.
	EBPFDiagnosticsStateNormal = "normal"
	// EBPFDiagnosticsStateWaitingForInterface is a configured data plane with
	// no matching interface available yet (for example, local TC configured
	// but no default route exists) -- not a failure, since there is nothing
	// to attach to.
	EBPFDiagnosticsStateWaitingForInterface = "waiting_for_interface"
	// EBPFDiagnosticsStateRecovering is a failure with a retry still
	// outstanding: the scheduler in interface_monitor.go is actively
	// retrying, no operator action is needed unless it persists.
	EBPFDiagnosticsStateRecovering = "recovering"
	// EBPFDiagnosticsStateNeedsAttention is a failure with no retry
	// outstanding for it (the backend reported itself closed or requiring a
	// rebuild -- see tcSharedRewriteUnrecoverable) or a bypass_rule_set
	// revert that itself failed, leaving backends disagreeing about policy.
	// Recovering on its own is not expected here; restarting the inbound
	// (or the whole process) is.
	EBPFDiagnosticsStateNeedsAttention = "needs_attention"
)

// BypassRuleSetBackendState is one backend's own confirmed position in the
// bypass_rule_set policy version sequence -- see EBPFDiagnostics'
// BypassRuleSetBackendState field doc comment for what Known=false means.
type BypassRuleSetBackendState struct {
	Version uint64 `json:"version"`
	Known   bool   `json:"known"`
}

// EBPFDiagnostics is one running eBPF inbound's actual interception state,
// as distinct from the static kernel-capability probe `sing-box tools ebpf
// status` reports: answering "is this configured inbound intercepting
// traffic right now" needs a running instance, not just kernel support, so
// this is computed from live state (Inbound.Diagnostics), not probed from a
// separate process.
type EBPFDiagnostics struct {
	Tag   string `json:"tag"`
	State string `json:"state"`

	LocalEnabled    bool   `json:"local_enabled"`
	LocalDataPlane  string `json:"local_data_plane,omitempty"`
	SharedEnabled   bool   `json:"shared_enabled"`
	SharedDataPlane string `json:"shared_data_plane,omitempty"`
	FakeIPICMPReply bool   `json:"fakeip_icmp_reply"`

	Attachments []EBPFAttachmentDiagnostics `json:"attachments,omitempty"`

	// LastError and LastErrorAt are the most recent warning recorded across
	// every category this inbound logs through (interface topology,
	// infrastructure, host policy, reconcile, bypass_rule_set policy, TCP,
	// UDP) -- whichever happened most recently, even if its own log line was
	// itself rate-limited into silence.
	LastError   string     `json:"last_error,omitempty"`
	LastErrorAt *time.Time `json:"last_error_at,omitempty"`
	// LastRecoveryAt is when a general-TC or shared-packet-rewrite failure
	// most recently cleared on its own. Nil if none has, in this process.
	LastRecoveryAt *time.Time `json:"last_recovery_at,omitempty"`
	// RecoveryPending is whether interface_monitor.go's scheduler currently
	// has an outstanding retry for general TC state or shared packet-rewrite.
	RecoveryPending bool `json:"recovery_pending"`
	// RecoveryUnrecoverable is whether general TC state or shared
	// packet-rewrite last reported itself unrecoverable (closed, or
	// requiring a rebuild the scheduler cannot perform on its own -- see
	// tcSharedRewriteUnrecoverable). Unlike RecoveryPending, no retry is
	// outstanding for this: State reports needs_attention for it
	// unconditionally, including ahead of waiting_for_interface, since an
	// attachment that still exists but is unrecoverable is not the same
	// situation as one that simply has not been created yet.
	RecoveryUnrecoverable bool `json:"recovery_unrecoverable"`
	// NextRetryAt is when interface_monitor.go's single retry timer is next
	// armed to fire, across all three of its components (shared
	// packet-rewrite, general TC, bypass_rule_set) -- nil when nothing is
	// currently outstanding, matching RecoveryPending/BypassRuleSetPending
	// both being false. Whichever component's own backoff is soonest is
	// what actually wakes the loop; this does not say which one.
	NextRetryAt *time.Time `json:"next_retry_at,omitempty"`

	// BypassRuleSetConsistent is false only when a compensating rollback
	// itself failed (see Inbound.bypassRuleSetInconsistent in
	// inbound_policy.go): backends are now known to disagree about the
	// bypass_rule_set policy, not just temporarily out of date.
	BypassRuleSetConsistent bool `json:"bypass_rule_set_consistent"`
	// BypassRuleSetPending is whether a previously-failed bypass_rule_set
	// refresh is still awaiting retry.
	BypassRuleSetPending bool `json:"bypass_rule_set_pending"`
	// BypassRuleSetPolicyVersion is the compiled bypass_rule_set policy's own
	// content-based version, naming the policy this inbound has last
	// CONFIRMED applying: it advances only when a fully successful apply's
	// content actually differs from what was in effect before it, so it
	// names which policy generation is current, not how many times an apply
	// has been attempted.
	//
	// BypassRuleSetExpectedPolicyVersion is the different thing a reader
	// needs while BypassRuleSetPending is true: the version of the most
	// recently ATTEMPTED policy, updated on every apply attempt regardless
	// of whether it succeeded -- "what this inbound is currently trying to
	// converge to". The two fields coincide exactly when nothing is
	// outstanding (BypassRuleSetPending=false and BypassRuleSetConsistent=true);
	// while a retry is pending, BypassRuleSetExpectedPolicyVersion names the
	// target a later retry is chasing, and BypassRuleSetPolicyVersion still
	// names whatever was last actually confirmed, lagging behind it by
	// construction -- neither value is wrong, they answer different
	// questions ("what do we want" vs. "what do we know we have").
	//
	// BypassRuleSetRetryCount counts a third, unrelated thing: how many
	// times the TC recovery scheduler has actually retried a
	// previously-failed apply. It does not include the original attempt for
	// a policy version, and it does not include a fresh apply triggered by
	// rule-set content actually changing -- both of those go through the
	// same apply function but are not retries of anything.
	BypassRuleSetPolicyVersion         uint64 `json:"bypass_rule_set_policy_version"`
	BypassRuleSetExpectedPolicyVersion uint64 `json:"bypass_rule_set_expected_policy_version"`
	BypassRuleSetRetryCount            uint64 `json:"bypass_rule_set_retry_count"`
	// BypassRuleSetBackendState records, per backend, the highest
	// BypassRuleSetPolicyVersion that backend's own forward apply or
	// compensating revert last actually completed successfully (Version), and
	// whether that is still trustworthy (Known). Known=false means the most
	// recent operation attempted on that backend -- always a compensating
	// revert, since a backend whose forward apply itself failed is never
	// considered "applied" in the first place -- did not complete
	// successfully: Version then names the last point that backend was
	// confirmed at, not a claim about what it is actually running now. Treat
	// Known=false as genuinely unknown, not as "probably still at Version";
	// this is exactly the condition BypassRuleSetConsistent=false reports at
	// the whole-inbound level. A backend missing from the map does not exist
	// for this inbound.
	BypassRuleSetBackendState map[string]BypassRuleSetBackendState `json:"bypass_rule_set_backend_state,omitempty"`

	// UDPSessionCount is the number of distinct UDP clients (by source
	// address:port) this inbound is currently tracking state for, summed
	// across every data plane that keeps its own client table: the local/TC
	// path and shared.data_plane: packet_rewrite, which are independent
	// tables and can each have their own, non-overlapping set of clients --
	// a packet_rewrite-only inbound with no local role at all previously
	// read 0 here regardless of how many clients were actually active,
	// since only the local/TC table was ever counted. This counts distinct
	// clients, not the number of destination bindings or flows any one
	// client may have open (a single client can hold several of those).
	UDPSessionCount int                        `json:"udp_session_count"`
	UDPReplySockets udpReplySocketPoolSnapshot `json:"udp_reply_sockets"`

	Counters EBPFCounters `json:"counters"`
}

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
	nextRetryAt time.Time
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

// DiagnosticsJSON satisfies experimental/clashapi's duck-typed
// ebpfDiagnosticsProvider interface, so the running Clash API server (when
// configured) can report this inbound's status without importing this
// package or its with_ebpf build tag.
func (i *Inbound) DiagnosticsJSON() any {
	return i.Diagnostics()
}

// Diagnostics reports this inbound's current interception state. Safe to
// call concurrently with normal operation; every field is read through the
// same locks the running data plane itself uses, so this never blocks
// longer than one of those already does elsewhere.
func (i *Inbound) Diagnostics() EBPFDiagnostics {
	diagnostics := EBPFDiagnostics{
		Tag:             i.Tag(),
		LocalEnabled:    i.localEnabled,
		SharedEnabled:   i.sharedEnabled,
		FakeIPICMPReply: i.fakeIPICMPReply,
	}
	if i.localEnabled {
		diagnostics.LocalDataPlane = i.localDataPlane
	}
	if i.sharedEnabled {
		diagnostics.SharedDataPlane = i.sharedDataPlane
	}

	i.tcDataPlaneAccess.RLock()
	tcDataPlane := i.tcDataPlane
	i.tcDataPlaneAccess.RUnlock()
	if tcDataPlane != nil {
		diagnostics.Attachments = append(diagnostics.Attachments, tcDataPlane.AttachmentDiagnostics()...)
	}
	if shared := i.sharedRewriteInstance(); shared != nil {
		if sharedDataPlane := shared.dataPlaneInstance(); sharedDataPlane != nil {
			diagnostics.Attachments = append(diagnostics.Attachments, sharedDataPlane.AttachmentDiagnostics()...)
		}
	}
	if i.localCgroupEnabled() {
		if backend := i.cgroupBackendInstance(); backend != nil && !backend.IsClosed() {
			diagnostics.Attachments = append(diagnostics.Attachments, EBPFAttachmentDiagnostics{
				InterfaceName: backend.CgroupPath(),
				Role:          "local",
				Mechanism:     "cgroup",
			})
		}
	}
	sort.Slice(diagnostics.Attachments, func(a, b int) bool {
		return diagnostics.Attachments[a].InterfaceName < diagnostics.Attachments[b].InterfaceName
	})

	var lastErrorAt time.Time
	for _, limiter := range []*warningLimiter{
		&i.interfaceWarnings.inventory,
		&i.interfaceWarnings.defaultInterface,
		&i.interfaceWarnings.topology,
		&i.interfaceWarnings.infrastructure,
		&i.interfaceWarnings.hostPolicy,
		&i.interfaceWarnings.reconcile,
		&i.interfaceWarnings.fakeIPICMPRoute,
		&i.policyWarnings,
		&i.tcpWarnings,
		&i.udpWarnings.packetInfo,
		&i.udpWarnings.originalDestination,
		&i.udpWarnings.cleanup,
		&i.udpWarnings.replySocketCapacity,
	} {
		message, at := limiter.last()
		if at.After(lastErrorAt) {
			lastErrorAt = at
			diagnostics.LastError = message
		}
	}
	if !lastErrorAt.IsZero() {
		diagnostics.LastErrorAt = &lastErrorAt
	}

	i.diagnostics.access.Lock()
	if i.diagnostics.haveOutcome {
		diagnostics.RecoveryPending = i.diagnostics.lastOutcome.general == tcSharedRewriteRecoverable ||
			i.diagnostics.lastOutcome.sharedRewrite == tcSharedRewriteRecoverable ||
			i.diagnostics.lastOutcome.bypassRuleSet == tcSharedRewriteRecoverable
		diagnostics.RecoveryUnrecoverable = i.diagnostics.lastOutcome.general == tcSharedRewriteUnrecoverable ||
			i.diagnostics.lastOutcome.sharedRewrite == tcSharedRewriteUnrecoverable ||
			i.diagnostics.lastOutcome.bypassRuleSet == tcSharedRewriteUnrecoverable
	}
	if !i.diagnostics.lastRecoveryAt.IsZero() {
		recoveryAt := i.diagnostics.lastRecoveryAt
		diagnostics.LastRecoveryAt = &recoveryAt
	}
	if !i.diagnostics.nextRetryAt.IsZero() {
		nextRetryAt := i.diagnostics.nextRetryAt
		diagnostics.NextRetryAt = &nextRetryAt
	}
	i.diagnostics.access.Unlock()

	i.bypassRuleSetAccess.Lock()
	diagnostics.BypassRuleSetConsistent = !i.bypassRuleSetInconsistent
	diagnostics.BypassRuleSetPending = i.bypassRuleSetNeedsRetry
	diagnostics.BypassRuleSetPolicyVersion = i.bypassRuleSetPolicyVersion
	diagnostics.BypassRuleSetExpectedPolicyVersion = i.bypassRuleSetExpectedVersion
	diagnostics.BypassRuleSetRetryCount = i.bypassRuleSetRetryCount
	backendState := make(map[string]BypassRuleSetBackendState, 3)
	if i.tcBackend() != nil {
		backendState["TC"] = BypassRuleSetBackendState{Version: i.bypassRuleSetTC.version, Known: i.bypassRuleSetTC.known}
	}
	if i.cgroupBackendInstance() != nil {
		backendState["cgroup"] = BypassRuleSetBackendState{Version: i.bypassRuleSetCgroup.version, Known: i.bypassRuleSetCgroup.known}
	}
	if shared := i.sharedRewriteInstance(); shared != nil && shared.sharedBackendInstance() != nil {
		backendState["shared"] = BypassRuleSetBackendState{Version: i.bypassRuleSetShared.version, Known: i.bypassRuleSetShared.known}
	}
	if len(backendState) > 0 {
		diagnostics.BypassRuleSetBackendState = backendState
	}
	i.bypassRuleSetAccess.Unlock()

	diagnostics.UDPSessionCount = i.udpClientTable.count()
	if shared := i.sharedRewriteInstance(); shared != nil {
		diagnostics.UDPSessionCount += shared.sharedUDPClientTable.count()
	}
	diagnostics.UDPReplySockets = i.udpReplySockets.snapshot()

	diagnostics.Counters = i.counters.snapshot()
	var sharedRewriteBackend *commonEBPF.SharedPacketRewriteBackend
	if shared := i.sharedRewriteInstance(); shared != nil {
		sharedRewriteBackend = shared.sharedBackendInstance()
	}
	if sharedRewriteBackend != nil {
		if failures, err := sharedRewriteBackend.TokenReservationFailures(); err == nil {
			diagnostics.Counters.TokenReservationFailures = failures
		}
		if failures, err := sharedRewriteBackend.RewriteFailures(); err == nil {
			diagnostics.Counters.RewriteFailures = failures
		}
	}
	// fakeip_icmp can be hosted independently by the TC backend (local TC,
	// shared socket_assign) and by the shared packet-rewrite backend at the
	// same time -- each loads its own copy of the object -- so their counts
	// are summed rather than one overwriting the other.
	addFakeIPICMPCounters(&diagnostics.Counters, i.tcBackend(), sharedRewriteBackend)

	diagnostics.State = deriveDiagnosticsState(diagnostics)
	return diagnostics
}

type fakeIPICMPCounterSource interface {
	ICMPEchoReplyEnabled() bool
	ICMPEchoReplyCount() (uint64, error)
	ICMPEchoPassThroughCount() (uint64, error)
	ICMPEchoRewriteFailureCount() (uint64, error)
}

func addFakeIPICMPCounters(counters *EBPFCounters, sources ...fakeIPICMPCounterSource) {
	for _, source := range sources {
		if source == nil || !source.ICMPEchoReplyEnabled() {
			continue
		}
		replies, _ := source.ICMPEchoReplyCount()
		passThrough, _ := source.ICMPEchoPassThroughCount()
		rewriteFailures, _ := source.ICMPEchoRewriteFailureCount()
		counters.FakeIPICMPReplies += replies
		counters.FakeIPICMPPassThrough += passThrough
		counters.FakeIPICMPRewriteFailureDrops += rewriteFailures
	}
}

// deriveDiagnosticsState computes EBPFDiagnostics.State from the rest of the
// struct.
func deriveDiagnosticsState(d EBPFDiagnostics) string {
	// Checked first, ahead of waiting_for_interface: an unrecoverable
	// component or an inconsistent bypass_rule_set both mean an operator
	// has to act, regardless of whether every configured data plane
	// happens to also have an attachment recorded right now. Reporting
	// waiting_for_interface here (as an attachment lingering in
	// EBPFDiagnostics.Attachments from before the backend gave up on it
	// would otherwise let through) would suggest the fix is "wait", when it
	// is not.
	if d.RecoveryUnrecoverable || !d.BypassRuleSetConsistent {
		return EBPFDiagnosticsStateNeedsAttention
	}
	if d.LocalEnabled && !attachmentHasRole(d.Attachments, "local") {
		return EBPFDiagnosticsStateWaitingForInterface
	}
	if d.SharedEnabled && !attachmentHasRole(d.Attachments, "shared") {
		return EBPFDiagnosticsStateWaitingForInterface
	}
	if d.RecoveryPending || d.BypassRuleSetPending {
		return EBPFDiagnosticsStateRecovering
	}
	return EBPFDiagnosticsStateNormal
}

func attachmentHasRole(attachments []EBPFAttachmentDiagnostics, role string) bool {
	for _, attachment := range attachments {
		if attachment.Role == role || attachment.Role == "local+shared" {
			return true
		}
	}
	return false
}

// WriteJSON writes d as JSON, matching the shape sing-ebpf's kernel-probe
// report already uses for `sing-box tools ebpf status --json`.
func (d EBPFDiagnostics) WriteJSON(w io.Writer) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(d)
}

// WriteText writes d as a short human-readable block.
func (d EBPFDiagnostics) WriteText(w io.Writer) error {
	lines := []string{
		fmt.Sprintf("Tag: %s", d.Tag),
		fmt.Sprintf("State: %s", d.State),
	}
	if d.LocalEnabled {
		lines = append(lines, fmt.Sprintf("Local data plane: %s", d.LocalDataPlane))
	}
	if d.SharedEnabled {
		lines = append(lines, fmt.Sprintf("Shared data plane: %s", d.SharedDataPlane))
	}
	lines = append(lines, fmt.Sprintf("FakeIP ICMP reply: %t", d.FakeIPICMPReply))
	if len(d.Attachments) == 0 {
		lines = append(lines, "Attachments: none")
	} else {
		lines = append(lines, "Attachments:")
		for _, attachment := range d.Attachments {
			framing := attachment.Framing
			if framing == "" {
				framing = "n/a"
			}
			lines = append(lines, fmt.Sprintf(
				"  %s: role=%s mechanism=%s framing=%s fakeip_icmp=%t",
				attachment.InterfaceName, attachment.Role, attachment.Mechanism, framing, attachment.ICMPEchoReply,
			))
		}
	}
	lines = append(lines, fmt.Sprintf("Recovery pending: %t", d.RecoveryPending))
	if d.RecoveryUnrecoverable {
		lines = append(lines, "Recovery unrecoverable: true")
	}
	if d.LastRecoveryAt != nil {
		lines = append(lines, fmt.Sprintf("Last recovery: %s", d.LastRecoveryAt.Format(time.RFC3339)))
	}
	if d.LastError != "" {
		lines = append(lines, fmt.Sprintf("Last error (%s): %s", d.LastErrorAt.Format(time.RFC3339), d.LastError))
	}
	lines = append(lines, fmt.Sprintf("bypass_rule_set: consistent=%t pending=%t", d.BypassRuleSetConsistent, d.BypassRuleSetPending))
	lines = append(lines, fmt.Sprintf("UDP sessions: %d", d.UDPSessionCount))
	lines = append(lines, fmt.Sprintf(
		"UDP reply sockets: count=%d peak=%d evicted=%d capacity_rejected=%d",
		d.UDPReplySockets.Count, d.UDPReplySockets.Peak, d.UDPReplySockets.Evicted, d.UDPReplySockets.CapacityRejected,
	))
	lines = append(lines, fmt.Sprintf(
		"Counters: assignment_lookup_failures=%d token_reservation_failures=%d rewrite_failures=%d "+
			"shared_reconcile_failures=%d recovery_attempts=%d recovery_successes=%d recovery_failures=%d",
		d.Counters.AssignmentLookupFailures, d.Counters.TokenReservationFailures, d.Counters.RewriteFailures,
		d.Counters.SharedReconcileFailures, d.Counters.RecoveryAttempts, d.Counters.RecoverySuccesses, d.Counters.RecoveryFailures,
	))
	lines = append(lines, fmt.Sprintf(
		"fakeip_icmp counters: replies=%d pass_through=%d rewrite_failure_drops=%d",
		d.Counters.FakeIPICMPReplies, d.Counters.FakeIPICMPPassThrough, d.Counters.FakeIPICMPRewriteFailureDrops,
	))
	for _, line := range lines {
		if _, err := io.WriteString(w, line+"\n"); err != nil {
			return err
		}
	}
	return nil
}

// logStartupSummary is startInbound's item-9 deliverable: a brief, always-
// visible (Info, not Debug) statement of which paths are enabled, what each
// actually mounted as (interface and mechanism, not just the configured
// data plane -- a config can ask for TCX and still land on clsact), which
// configured paths have no interface to attach to yet, and which
// attachments fakeip_icmp actually covers. It is built from the same
// Diagnostics this inbound already computes for external queries, so the
// summary can never say something the diagnostics endpoint would disagree
// with a moment later.
//
// This does not replace startInbound's existing Debug-level line: that one
// is a complete dump meant for deep troubleshooting (routing marks, listener
// modes, and so on); this one is the handful of facts an operator actually
// wants to see once, right after startup, at the log level they normally run.
func (i *Inbound) logStartupSummary() {
	diagnostics := i.Diagnostics()

	paths := make([]string, 0, 2)
	if diagnostics.LocalEnabled {
		paths = append(paths, "local="+diagnostics.LocalDataPlane)
	}
	if diagnostics.SharedEnabled {
		paths = append(paths, "shared="+diagnostics.SharedDataPlane)
	}
	pathsSummary := "none"
	if len(paths) > 0 {
		pathsSummary = strings.Join(paths, ", ")
	}

	mountsSummary := "none"
	if len(diagnostics.Attachments) > 0 {
		mounts := make([]string, 0, len(diagnostics.Attachments))
		for _, attachment := range diagnostics.Attachments {
			mounts = append(mounts, fmt.Sprintf("%s(%s,%s)", attachment.InterfaceName, attachment.Role, attachment.Mechanism))
		}
		mountsSummary = strings.Join(mounts, ", ")
	}

	waiting := make([]string, 0, 2)
	if diagnostics.LocalEnabled && !attachmentHasRole(diagnostics.Attachments, "local") {
		waiting = append(waiting, "local")
	}
	if diagnostics.SharedEnabled && !attachmentHasRole(diagnostics.Attachments, "shared") {
		waiting = append(waiting, "shared")
	}
	waitingSummary := "none"
	if len(waiting) > 0 {
		waitingSummary = strings.Join(waiting, ", ")
	}

	fakeIPICMPSummary := "off"
	if diagnostics.FakeIPICMPReply {
		covered := make([]string, 0, len(diagnostics.Attachments))
		for _, attachment := range diagnostics.Attachments {
			if attachment.ICMPEchoReply {
				covered = append(covered, attachment.InterfaceName+"("+attachment.Role+")")
			}
		}
		fakeIPICMPSummary = "enabled, not yet covering any attachment"
		if len(covered) > 0 {
			fakeIPICMPSummary = strings.Join(covered, ", ")
		}
	}

	i.logger.Debug(
		"eBPF inbound started: paths=[", pathsSummary, "] mounts=[", mountsSummary,
		"] waiting_for_interface=[", waitingSummary, "] fakeip_icmp=[", fakeIPICMPSummary, "]",
	)
}
