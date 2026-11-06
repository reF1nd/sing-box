//go:build with_ebpf && (linux || android)

package ebpf

import (
	"time"

	commonEBPF "github.com/CHIZI-0618/sing-ebpf"
)

// EBPFAttachmentDiagnostics describes one place this inbound is actually
// intercepting traffic right now: either a TC attachment on a network
// interface, or (Mechanism == "cgroup") the cgroup local data plane, which
// has no per-interface attachment of its own.
type EBPFAttachmentDiagnostics = commonEBPF.AttachmentInfo

type ebpfAttachmentLogSummary struct {
	Interface string `json:"interface"`
	Role      string `json:"role"`
	Mechanism string `json:"mechanism"`
}

// Runtime states EBPFDiagnostics.State reports. These summarize the fields
// below into the one value most operators actually want at a glance; the
// individual fields remain available for anything more specific.
const (
	ebpfDiagnosticsAPICacheTTL = 500 * time.Millisecond

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

// BypassRuleSetBackendState is one backend's own confirmed position in a
// path-scoped bypass_rule_set policy version sequence.
type BypassRuleSetBackendState struct {
	Version uint64 `json:"version"`
	Known   bool   `json:"known"`
}

type scopedBypassRuleSetDiagnostics struct {
	Consistent            bool
	Pending               bool
	PolicyVersion         uint64
	ExpectedPolicyVersion uint64
	RetryCount            uint64
	BackendState          map[string]BypassRuleSetBackendState
}

// EBPFPolicyEpochDiagnostics makes the two independently updated policy
// scopes explicit. A single scalar generation would be misleading because a
// local update can succeed while a shared update is still pending.
type EBPFPolicyEpochDiagnostics struct {
	LocalConfirmed  uint64 `json:"local_confirmed"`
	LocalExpected   uint64 `json:"local_expected"`
	SharedConfirmed uint64 `json:"shared_confirmed"`
	SharedExpected  uint64 `json:"shared_expected"`
	Converged       bool   `json:"converged"`
}

// UDPNATDiagnostics reports event-driven userspace UDP NAT state. Cache
// insertion and capacity-eviction totals come from sing/freelru's existing
// metrics and therefore restart when the cache is purged (for example after a
// network change). The remaining counters are touched only on drops or
// socket-release events, so collecting them adds no packet-path polling.
type UDPNATDiagnostics struct {
	ActiveSessions                 int    `json:"active_sessions"`
	CreatedSessions                uint64 `json:"created_sessions"`
	CapacityEvictions              uint64 `json:"capacity_evictions"`
	QueueDrops                     uint64 `json:"queue_drops"`
	SocketReleaseEvents            uint64 `json:"socket_release_events"`
	SocketReleaseMatched           uint64 `json:"socket_release_matched"`
	PendingReleaseCapacityRejected uint64 `json:"pending_release_capacity_rejected"`
	ReleaseNotificationDrops       uint64 `json:"release_notification_drops"`
	RedirectAdmissionFailures      uint64 `json:"redirect_admission_failures,omitempty"`
	UDPTokenAdmissionFailures      uint64 `json:"udp_token_admission_failures,omitempty"`
	UDPTokenReverseFailures        uint64 `json:"udp_token_reverse_failures,omitempty"`
	UDPPeerAdmissionFailures       uint64 `json:"udp_peer_admission_failures,omitempty"`
	TCPPeerAdmissionFailures       uint64 `json:"tcp_peer_admission_failures,omitempty"`
	UDPRecoveryAdmissionFailures   uint64 `json:"udp_recovery_admission_failures,omitempty"`
}

func (d *UDPNATDiagnostics) add(other UDPNATDiagnostics) {
	d.ActiveSessions += other.ActiveSessions
	d.CreatedSessions += other.CreatedSessions
	d.CapacityEvictions += other.CapacityEvictions
	d.QueueDrops += other.QueueDrops
	d.SocketReleaseEvents += other.SocketReleaseEvents
	d.SocketReleaseMatched += other.SocketReleaseMatched
	d.PendingReleaseCapacityRejected += other.PendingReleaseCapacityRejected
	d.ReleaseNotificationDrops += other.ReleaseNotificationDrops
	d.RedirectAdmissionFailures += other.RedirectAdmissionFailures
	d.UDPTokenAdmissionFailures += other.UDPTokenAdmissionFailures
	d.UDPTokenReverseFailures += other.UDPTokenReverseFailures
	d.UDPPeerAdmissionFailures += other.UDPPeerAdmissionFailures
	d.TCPPeerAdmissionFailures += other.TCPPeerAdmissionFailures
	d.UDPRecoveryAdmissionFailures += other.UDPRecoveryAdmissionFailures
}

// EBPFDiagnostics is one running eBPF inbound's actual interception state,
// as distinct from the static kernel-capability probe `sing-box tools ebpf
// status` reports: answering "is this configured inbound intercepting
// traffic right now" needs a running instance, not just kernel support, so
// this is computed from live state (Inbound.Diagnostics), not probed from a
// separate process.
type EBPFDiagnostics struct {
	SchemaVersion int       `json:"schema_version"`
	ObservedAt    time.Time `json:"observed_at"`
	Tag           string    `json:"tag"`
	State         string    `json:"state"`

	LocalEnabled                    bool       `json:"local_enabled"`
	LocalDataPlane                  string     `json:"local_data_plane,omitempty"`
	LocalCgroupAttachMode           string     `json:"local_cgroup_attach_mode,omitempty"`
	LocalSelfBypassDecision         string     `json:"local_self_bypass_decision_backend,omitempty"`
	LocalSelfBypassProducer         string     `json:"local_self_bypass_producer_backend,omitempty"`
	LocalSelfBypassVisibility       string     `json:"local_self_bypass_visibility_backend,omitempty"`
	LocalSelfBypassCleanup          string     `json:"local_self_bypass_cleanup_backend,omitempty"`
	LocalSelfBypassReclaim          string     `json:"local_self_bypass_reclaim_backend,omitempty"`
	LocalSelfBypassAttachment       string     `json:"local_self_bypass_attachment_backend,omitempty"`
	LocalSelfBypassFallbackReason   string     `json:"local_self_bypass_fallback_reason,omitempty"`
	LocalSelfBypassReclaimAttempts  uint64     `json:"local_self_bypass_reclaim_attempts,omitempty"`
	LocalSelfBypassReclaimedSockets uint64     `json:"local_self_bypass_reclaimed_sockets,omitempty"`
	LocalSelfBypassReclaimFailures  uint64     `json:"local_self_bypass_reclaim_failures,omitempty"`
	LocalSelfBypassReclaimLastAt    *time.Time `json:"local_self_bypass_reclaim_last_at,omitempty"`
	LocalSelfBypassStorageFailures  uint64     `json:"local_self_bypass_storage_write_failures,omitempty"`
	LocalSelfBypassCookieFallbacks  uint64     `json:"local_self_bypass_cookie_fallbacks,omitempty"`
	LocalUDPCleanupMode             string     `json:"local_udp_cleanup_mode,omitempty"`
	LocalUDPUserspaceCleanupMode    string     `json:"local_udp_userspace_cleanup_mode,omitempty"`
	LocalUDPStorageMode             string     `json:"local_udp_storage_mode,omitempty"`
	LocalUDPTimeMode                string     `json:"local_udp_time_mode,omitempty"`
	LocalUDPState                   string     `json:"local_udp_state,omitempty"`
	LocalUDPRecoveryMode            string     `json:"local_udp_recovery_mode,omitempty"`
	LocalUDPMapPressure             string     `json:"local_udp_map_pressure,omitempty"`
	LocalUDPNetworkGeneration       uint32     `json:"local_udp_network_generation,omitempty"`
	LocalUDPReleaseObserver         bool       `json:"local_udp_release_observer"`
	LocalUDPReleaseFallbackReason   string     `json:"local_udp_release_fallback_reason,omitempty"`
	LocalUDPReleaseProgram          string     `json:"local_udp_release_program,omitempty"`
	SharedEnabled                   bool       `json:"shared_enabled"`
	SharedDataPlane                 string     `json:"shared_data_plane,omitempty"`
	FakeIPICMPReply                 bool       `json:"fakeip_icmp_reply"`
	TCBackendMode                   string     `json:"tc_backend_mode,omitempty"`
	TCListenerLookupMode            string     `json:"tc_listener_lookup_mode,omitempty"`
	TCAttachmentMode                string     `json:"tc_attachment_mode,omitempty"`
	TCDeliveryInterface             string     `json:"tc_delivery_interface,omitempty"`
	TCNetworkNamespace              string     `json:"tc_network_namespace,omitempty"`
	TCDeliveryInterfaceIndex        int        `json:"tc_delivery_interface_index,omitempty"`
	TCRoutingMark                   uint32     `json:"tc_routing_mark,omitempty"`
	TCRoutingTable                  int        `json:"tc_routing_table,omitempty"`
	TCRoutingPriority               int        `json:"tc_routing_priority,omitempty"`
	TCRoutingSlot                   int        `json:"tc_routing_slot,omitempty"`
	TCAttachmentCount               int        `json:"tc_attachment_count,omitempty"`
	TCRetiredAttachmentCount        int        `json:"tc_retired_attachment_count,omitempty"`
	TCRetiredDeliveryCount          int        `json:"tc_retired_delivery_count,omitempty"`
	TCRequiresRebuild               bool       `json:"tc_requires_rebuild"`
	TCHealthStatus                  string     `json:"tc_health_status,omitempty"`
	TCLastHealthCheckAt             *time.Time `json:"tc_last_health_check_at,omitempty"`
	TCLastReconcileAt               *time.Time `json:"tc_last_reconcile_at,omitempty"`
	TCNetworkGeneration             uint64     `json:"tc_network_generation,omitempty"`
	TCReturnSweepEntries            uint64     `json:"tc_return_sweep_entries"`
	TCReturnSweepCapacity           uint64     `json:"tc_return_sweep_capacity"`
	TCReturnSweepScanned            uint64     `json:"tc_return_sweep_scanned"`
	TCReturnSweepRemoved            uint64     `json:"tc_return_sweep_removed"`
	TCAssignmentSweepUsageKnown     bool       `json:"tc_assignment_sweep_usage_known"`
	TCReturnSweepUsageKnown         bool       `json:"tc_return_sweep_usage_known"`
	TCAssignmentSweepFailureMap     string     `json:"tc_assignment_sweep_failure_map"`
	TCAssignmentSweepScanned        uint64     `json:"tc_assignment_sweep_scanned,omitempty"`
	TCAssignmentSweepRemoved        uint64     `json:"tc_assignment_sweep_removed,omitempty"`
	TCAssignmentSweepMissing        uint64     `json:"tc_assignment_sweep_missing,omitempty"`
	TCAssignmentSweepSuperseded     uint64     `json:"tc_assignment_sweep_superseded,omitempty"`
	TCAssignmentSweepInFlight       uint64     `json:"tc_assignment_sweep_in_flight,omitempty"`
	TCAssignmentSweepComplete       bool       `json:"tc_assignment_sweep_complete"`
	TCAssignmentSweepEntries        uint64     `json:"tc_assignment_sweep_entries,omitempty"`
	TCAssignmentSweepCapacity       uint64     `json:"tc_assignment_sweep_capacity,omitempty"`
	TCAssignmentSweepPressure       bool       `json:"tc_assignment_sweep_pressure"`
	TCAssignmentSweepRuns           uint64     `json:"tc_assignment_sweep_runs,omitempty"`
	TCAssignmentSweepPartial        uint64     `json:"tc_assignment_sweep_partial,omitempty"`
	TCAssignmentSweepFailure        string     `json:"tc_assignment_sweep_failure,omitempty"`
	TCAssignmentSweepLastAt         *time.Time `json:"tc_assignment_sweep_last_at,omitempty"`
	TCAssignmentSweepPartialAt      *time.Time `json:"tc_assignment_sweep_partial_at,omitempty"`
	CgroupRecoveryQueueOverflows    uint64     `json:"cgroup_recovery_queue_overflows,omitempty"`
	CgroupRecoveryQueueOverflowAt   *time.Time `json:"cgroup_recovery_queue_overflow_at,omitempty"`
	WaitingRoles                    []string   `json:"waiting_roles,omitempty"`
	WaitingInterfaces               []string   `json:"waiting_interfaces,omitempty"`

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
	// currently outstanding, matching RecoveryPending and the scoped
	// local/shared bypass-rule-set pending fields
	// both being false. Whichever component's own backoff is soonest is
	// what actually wakes the loop; this does not say which one.
	NextRetryAt *time.Time `json:"next_retry_at,omitempty"`

	LocalBypassRuleSet  scopedBypassRuleSetDiagnostics `json:"local_bypass_rule_set"`
	SharedBypassRuleSet scopedBypassRuleSetDiagnostics `json:"shared_bypass_rule_set"`
	PolicyEpoch         EBPFPolicyEpochDiagnostics     `json:"policy_epoch"`

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
	UDPNAT          UDPNATDiagnostics          `json:"udp_nat"`
	UDPReplySockets udpReplySocketPoolSnapshot `json:"udp_reply_sockets"`

	Counters EBPFCounters `json:"counters"`
}

type udpReleasePathDiagnostics interface {
	UDPReleasePathDiagnostics() (bool, string, string)
}
