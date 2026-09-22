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

	"github.com/sagernet/sing-box/adapter"

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

	LocalEnabled                 bool       `json:"local_enabled"`
	LocalDataPlane               string     `json:"local_data_plane,omitempty"`
	LocalCgroupAttachMode        string     `json:"local_cgroup_attach_mode,omitempty"`
	LocalUDPCleanupMode          string     `json:"local_udp_cleanup_mode,omitempty"`
	LocalUDPUserspaceCleanupMode string     `json:"local_udp_userspace_cleanup_mode,omitempty"`
	LocalUDPStorageMode          string     `json:"local_udp_storage_mode,omitempty"`
	LocalUDPTimeMode             string     `json:"local_udp_time_mode,omitempty"`
	SharedEnabled                bool       `json:"shared_enabled"`
	SharedDataPlane              string     `json:"shared_data_plane,omitempty"`
	FakeIPICMPReply              bool       `json:"fakeip_icmp_reply"`
	TCBackendMode                string     `json:"tc_backend_mode,omitempty"`
	TCListenerLookupMode         string     `json:"tc_listener_lookup_mode,omitempty"`
	TCAttachmentMode             string     `json:"tc_attachment_mode,omitempty"`
	TCDeliveryInterface          string     `json:"tc_delivery_interface,omitempty"`
	TCDeliveryInterfaceIndex     int        `json:"tc_delivery_interface_index,omitempty"`
	TCRoutingMark                uint32     `json:"tc_routing_mark,omitempty"`
	TCRoutingTable               int        `json:"tc_routing_table,omitempty"`
	TCRoutingPriority            int        `json:"tc_routing_priority,omitempty"`
	TCAttachmentCount            int        `json:"tc_attachment_count,omitempty"`
	TCRetiredAttachmentCount     int        `json:"tc_retired_attachment_count,omitempty"`
	TCRetiredDeliveryCount       int        `json:"tc_retired_delivery_count,omitempty"`
	TCRequiresRebuild            bool       `json:"tc_requires_rebuild"`
	TCHealthStatus               string     `json:"tc_health_status,omitempty"`
	TCLastHealthCheckAt          *time.Time `json:"tc_last_health_check_at,omitempty"`
	TCLastReconcileAt            *time.Time `json:"tc_last_reconcile_at,omitempty"`
	TCNetworkGeneration          uint64     `json:"tc_network_generation,omitempty"`

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

// EBPFDiagnostics exposes a request-driven snapshot through the sing-box API.
// The adapter form keeps daemon and service/api independent of this optional
// build-tagged package and of sing-ebpf's concrete types.
func (i *Inbound) EBPFDiagnostics() adapter.EBPFRuntimeDiagnostics {
	now := time.Now()
	i.diagnosticsAPIAccess.Lock()
	defer i.diagnosticsAPIAccess.Unlock()
	if !i.diagnosticsAPIAt.IsZero() && now.Sub(i.diagnosticsAPIAt) < ebpfDiagnosticsAPICacheTTL {
		return i.diagnosticsAPIValue
	}
	diagnostics := diagnosticsForAPI(i.Diagnostics())
	i.diagnosticsAPIAt = now
	i.diagnosticsAPIValue = diagnostics
	return diagnostics
}

func diagnosticsForAPI(diagnostics EBPFDiagnostics) adapter.EBPFRuntimeDiagnostics {
	attachments := make([]adapter.EBPFAttachmentDiagnostics, 0, len(diagnostics.Attachments))
	for _, attachment := range diagnostics.Attachments {
		attachments = append(attachments, adapter.EBPFAttachmentDiagnostics{
			InterfaceName:  attachment.InterfaceName,
			InterfaceIndex: attachment.InterfaceIndex,
			Role:           attachment.Role,
			Framing:        attachment.Framing,
			Mechanism:      attachment.Mechanism,
			ICMPEchoReply:  attachment.ICMPEchoReply,
		})
	}
	return adapter.EBPFRuntimeDiagnostics{
		SchemaVersion:                diagnostics.SchemaVersion,
		ObservedAt:                   diagnostics.ObservedAt,
		Tag:                          diagnostics.Tag,
		State:                        diagnostics.State,
		LocalEnabled:                 diagnostics.LocalEnabled,
		LocalDataPlane:               diagnostics.LocalDataPlane,
		LocalCgroupAttachMode:        diagnostics.LocalCgroupAttachMode,
		LocalUDPCleanupMode:          diagnostics.LocalUDPCleanupMode,
		LocalUDPUserspaceCleanupMode: diagnostics.LocalUDPUserspaceCleanupMode,
		LocalUDPStorageMode:          diagnostics.LocalUDPStorageMode,
		LocalUDPTimeMode:             diagnostics.LocalUDPTimeMode,
		SharedEnabled:                diagnostics.SharedEnabled,
		SharedDataPlane:              diagnostics.SharedDataPlane,
		FakeIPICMPReply:              diagnostics.FakeIPICMPReply,
		TCBackendMode:                diagnostics.TCBackendMode,
		TCListenerLookupMode:         diagnostics.TCListenerLookupMode,
		TCAttachmentMode:             diagnostics.TCAttachmentMode,
		TCDeliveryInterface:          diagnostics.TCDeliveryInterface,
		TCDeliveryInterfaceIndex:     diagnostics.TCDeliveryInterfaceIndex,
		TCRoutingMark:                diagnostics.TCRoutingMark,
		TCRoutingTable:               diagnostics.TCRoutingTable,
		TCRoutingPriority:            diagnostics.TCRoutingPriority,
		TCAttachmentCount:            diagnostics.TCAttachmentCount,
		TCRetiredAttachmentCount:     diagnostics.TCRetiredAttachmentCount,
		TCRetiredDeliveryCount:       diagnostics.TCRetiredDeliveryCount,
		TCRequiresRebuild:            diagnostics.TCRequiresRebuild,
		TCHealthStatus:               diagnostics.TCHealthStatus,
		TCLastHealthCheckAt:          diagnostics.TCLastHealthCheckAt,
		TCLastReconcileAt:            diagnostics.TCLastReconcileAt,
		TCNetworkGeneration:          diagnostics.TCNetworkGeneration,
		Attachments:                  attachments,
		LastError:                    diagnostics.LastError,
		LastErrorAt:                  diagnostics.LastErrorAt,
		LastRecoveryAt:               diagnostics.LastRecoveryAt,
		RecoveryPending:              diagnostics.RecoveryPending,
		RecoveryUnrecoverable:        diagnostics.RecoveryUnrecoverable,
		NextRetryAt:                  diagnostics.NextRetryAt,
		LocalBypassRuleSet: adapter.EBPFBypassRuleSetDiagnostics{
			Consistent:            diagnostics.LocalBypassRuleSet.Consistent,
			Pending:               diagnostics.LocalBypassRuleSet.Pending,
			PolicyVersion:         diagnostics.LocalBypassRuleSet.PolicyVersion,
			ExpectedPolicyVersion: diagnostics.LocalBypassRuleSet.ExpectedPolicyVersion,
			RetryCount:            diagnostics.LocalBypassRuleSet.RetryCount,
			BackendState:          convertBypassRuleSetBackendState(diagnostics.LocalBypassRuleSet.BackendState),
		},
		SharedBypassRuleSet: adapter.EBPFBypassRuleSetDiagnostics{
			Consistent:            diagnostics.SharedBypassRuleSet.Consistent,
			Pending:               diagnostics.SharedBypassRuleSet.Pending,
			PolicyVersion:         diagnostics.SharedBypassRuleSet.PolicyVersion,
			ExpectedPolicyVersion: diagnostics.SharedBypassRuleSet.ExpectedPolicyVersion,
			RetryCount:            diagnostics.SharedBypassRuleSet.RetryCount,
			BackendState:          convertBypassRuleSetBackendState(diagnostics.SharedBypassRuleSet.BackendState),
		},
		UDPSessionCount: diagnostics.UDPSessionCount,
		UDPNAT: adapter.EBPFUDPNATDiagnostics{
			ActiveSessions:                 diagnostics.UDPNAT.ActiveSessions,
			CreatedSessions:                diagnostics.UDPNAT.CreatedSessions,
			CapacityEvictions:              diagnostics.UDPNAT.CapacityEvictions,
			QueueDrops:                     diagnostics.UDPNAT.QueueDrops,
			SocketReleaseEvents:            diagnostics.UDPNAT.SocketReleaseEvents,
			SocketReleaseMatched:           diagnostics.UDPNAT.SocketReleaseMatched,
			PendingReleaseCapacityRejected: diagnostics.UDPNAT.PendingReleaseCapacityRejected,
			ReleaseNotificationDrops:       diagnostics.UDPNAT.ReleaseNotificationDrops,
		},
		UDPReplySockets: adapter.EBPFUDPReplySocketDiagnostics{
			Count:            diagnostics.UDPReplySockets.Count,
			Peak:             diagnostics.UDPReplySockets.Peak,
			Evicted:          diagnostics.UDPReplySockets.Evicted,
			CapacityRejected: diagnostics.UDPReplySockets.CapacityRejected,
		},
		Counters: adapter.EBPFCounters{
			AssignmentLookupFailures:      diagnostics.Counters.AssignmentLookupFailures,
			TCSocketLookupFailures:        diagnostics.Counters.TCSocketLookupFailures,
			TCSKAssignFailures:            diagnostics.Counters.TCSKAssignFailures,
			TCAssignmentUpdateFailures:    diagnostics.Counters.TCAssignmentUpdateFailures,
			TCLocalFragmentPasses:         diagnostics.Counters.TCLocalFragmentPasses,
			TCSharedFragmentPasses:        diagnostics.Counters.TCSharedFragmentPasses,
			TokenReservationFailures:      diagnostics.Counters.TokenReservationFailures,
			RewriteFailures:               diagnostics.Counters.RewriteFailures,
			SharedIngressFragmentPasses:   diagnostics.Counters.SharedIngressFragmentPasses,
			SharedEgressFragmentPasses:    diagnostics.Counters.SharedEgressFragmentPasses,
			SharedReconcileFailures:       diagnostics.Counters.SharedReconcileFailures,
			RecoveryAttempts:              diagnostics.Counters.RecoveryAttempts,
			RecoverySuccesses:             diagnostics.Counters.RecoverySuccesses,
			RecoveryFailures:              diagnostics.Counters.RecoveryFailures,
			FakeIPICMPReplies:             diagnostics.Counters.FakeIPICMPReplies,
			FakeIPICMPPassThrough:         diagnostics.Counters.FakeIPICMPPassThrough,
			FakeIPICMPRewriteFailureDrops: diagnostics.Counters.FakeIPICMPRewriteFailureDrops,
		},
	}
}

func convertBypassRuleSetBackendState(states map[string]BypassRuleSetBackendState) map[string]adapter.EBPFBypassRuleSetBackendState {
	converted := make(map[string]adapter.EBPFBypassRuleSetBackendState, len(states))
	for name, state := range states {
		converted[name] = adapter.EBPFBypassRuleSetBackendState{Version: state.Version, Known: state.Known}
	}
	return converted
}

func (i *Inbound) EBPFKernelRuntime() adapter.EBPFKernelRuntimeDiagnostics {
	now := time.Now()
	i.kernelRuntimeAPIAccess.Lock()
	defer i.kernelRuntimeAPIAccess.Unlock()
	if !i.kernelRuntimeAPIAt.IsZero() && now.Sub(i.kernelRuntimeAPIAt) < ebpfDiagnosticsAPICacheTTL {
		return i.kernelRuntimeAPIValue
	}
	diagnostics := kernelRuntimeForAPI(now, commonEBPF.InspectRuntimeState())
	i.kernelRuntimeAPIAt = now
	i.kernelRuntimeAPIValue = diagnostics
	return diagnostics
}

func kernelRuntimeForAPI(observedAt time.Time, runtimeState commonEBPF.RuntimeState) adapter.EBPFKernelRuntimeDiagnostics {
	programs := make([]adapter.EBPFProgramDiagnostics, 0, len(runtimeState.Programs))
	for _, program := range runtimeState.Programs {
		mapIDs := make([]uint32, len(program.MapIDs))
		for index, mapID := range program.MapIDs {
			mapIDs[index] = uint32(mapID)
		}
		programs = append(programs, adapter.EBPFProgramDiagnostics{
			ID:       uint32(program.ID),
			Name:     program.Name,
			Type:     program.Type.String(),
			MapCount: program.MapCount,
			MapIDs:   mapIDs,
		})
	}
	maps := make([]adapter.EBPFMapDiagnostics, 0, len(runtimeState.MapOccupancy.Maps))
	for _, item := range runtimeState.MapOccupancy.Maps {
		maps = append(maps, adapter.EBPFMapDiagnostics{
			ID:         uint32(item.ID),
			Name:       item.Name,
			Type:       item.Type,
			MaxEntries: item.MaxEntries,
			KeySize:    item.KeySize,
			ValueSize:  item.ValueSize,
			Flags:      item.Flags,
			Entries:    item.Entries,
			Supported:  item.Supported,
			Error:      item.Error,
		})
	}
	diagnostics := adapter.EBPFKernelRuntimeDiagnostics{
		ObservedAt: observedAt,
		Programs:   programs,
		MapOccupancy: adapter.EBPFMapOccupancyDiagnostics{
			Status: runtimeState.MapOccupancy.Status,
			Maps:   maps,
			Error:  runtimeState.MapOccupancy.Error,
		},
	}
	if runtimeState.ProgramsError != nil {
		diagnostics.ProgramsError = runtimeState.ProgramsError.Error()
	}
	return diagnostics
}

// Diagnostics reports this inbound's current interception state. Safe to
// call concurrently with normal operation; every field is read through the
// same locks the running data plane itself uses, so this never blocks
// longer than one of those already does elsewhere.
func (i *Inbound) Diagnostics() EBPFDiagnostics {
	diagnostics := EBPFDiagnostics{
		SchemaVersion:   adapter.EBPFDiagnosticsSchemaVersion,
		ObservedAt:      time.Now(),
		Tag:             i.Tag(),
		LocalEnabled:    i.localEnabled,
		SharedEnabled:   i.sharedEnabled,
		FakeIPICMPReply: i.fakeIPICMPReply,
	}
	if i.localEnabled {
		diagnostics.LocalDataPlane = i.localDataPlane
	}
	if backend := i.cgroupBackendInstance(); backend != nil && !backend.IsClosed() {
		diagnostics.LocalCgroupAttachMode = backend.AttachMode()
		diagnostics.LocalUDPCleanupMode = backend.UDPCleanupMode()
		diagnostics.LocalUDPUserspaceCleanupMode = backend.UDPUserspaceCleanupMode()
		diagnostics.LocalUDPStorageMode = backend.UDPStorageMode()
		diagnostics.LocalUDPTimeMode = backend.UDPTimeMode()
	}
	if i.sharedEnabled {
		diagnostics.SharedDataPlane = i.sharedDataPlane
	}

	i.tcDataPlaneAccess.RLock()
	tcDataPlane := i.tcDataPlane
	i.tcDataPlaneAccess.RUnlock()
	if tcDataPlane != nil {
		diagnostics.Attachments = append(diagnostics.Attachments, tcDataPlane.AttachmentDiagnostics()...)
		tc := tcDataPlane.TCDiagnostics()
		diagnostics.TCListenerLookupMode = tc.ListenerLookupMode
		diagnostics.TCAttachmentMode = tc.AttachmentMode
		diagnostics.TCDeliveryInterface = tc.NetworkInfo.DeliveryInterface
		diagnostics.TCDeliveryInterfaceIndex = tc.NetworkInfo.DeliveryInterfaceIndex
		diagnostics.TCRoutingMark = tc.NetworkInfo.RoutingMark
		diagnostics.TCRoutingTable = tc.NetworkInfo.RoutingTable
		diagnostics.TCRoutingPriority = tc.NetworkInfo.RoutingPriority
		diagnostics.TCAttachmentCount = tc.AttachmentCount
		diagnostics.TCRetiredAttachmentCount = tc.RetiredAttachmentCount
		diagnostics.TCRetiredDeliveryCount = tc.RetiredDeliveryCount
		diagnostics.TCRequiresRebuild = tc.RequiresRebuild
		diagnostics.TCBackendMode = "socket_assign"
		if tc.RequiresRebuild {
			diagnostics.TCHealthStatus = "needs_reconcile"
		} else if tc.AttachmentCount == 0 {
			diagnostics.TCHealthStatus = "waiting_for_interface"
		} else {
			diagnostics.TCHealthStatus = "attached"
		}
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
	limiters := []*warningLimiter{
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
	}
	if shared := i.sharedRewriteInstance(); shared != nil {
		limiters = append(limiters,
			&shared.tcpWarnings,
			&shared.janitorWarnings,
			&shared.udpWarnings.packetInfo,
			&shared.udpWarnings.originalDestination,
			&shared.udpWarnings.cleanup,
			&shared.udpWarnings.replySocketCapacity,
		)
	}
	for _, limiter := range limiters {
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
	if !i.diagnostics.lastHealthCheckAt.IsZero() {
		healthAt := i.diagnostics.lastHealthCheckAt
		diagnostics.TCLastHealthCheckAt = &healthAt
		if !i.diagnostics.lastHealthHealthy && diagnostics.TCHealthStatus == "attached" {
			diagnostics.TCHealthStatus = "degraded"
		}
	}
	if !i.diagnostics.lastReconcileAt.IsZero() {
		reconcileAt := i.diagnostics.lastReconcileAt
		diagnostics.TCLastReconcileAt = &reconcileAt
	}
	diagnostics.TCNetworkGeneration = i.networkGeneration
	if i.diagnostics.haveOutcome {
		diagnostics.RecoveryPending = i.diagnostics.lastOutcome.general == tcSharedRewriteRecoverable ||
			i.diagnostics.lastOutcome.sharedRewrite == tcSharedRewriteRecoverable ||
			i.diagnostics.lastOutcome.bypassRuleSet == tcSharedRewriteRecoverable
		diagnostics.RecoveryUnrecoverable = i.diagnostics.lastOutcome.general == tcSharedRewriteUnrecoverable ||
			i.diagnostics.lastOutcome.sharedRewrite == tcSharedRewriteUnrecoverable ||
			i.diagnostics.lastOutcome.bypassRuleSet == tcSharedRewriteUnrecoverable
	}
	if diagnostics.TCHealthStatus != "" {
		if diagnostics.RecoveryUnrecoverable {
			diagnostics.TCHealthStatus = "needs_reconcile"
		} else if diagnostics.RecoveryPending {
			diagnostics.TCHealthStatus = "recovering"
		}
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
	localState := scopedBypassRuleSetDiagnostics{
		Consistent:            !i.bypassRuleSetInconsistent,
		Pending:               i.bypassRuleSetNeedsRetry,
		PolicyVersion:         i.bypassRuleSetPolicyVersion,
		ExpectedPolicyVersion: i.bypassRuleSetExpectedVersion,
		RetryCount:            i.bypassRuleSetRetryCount,
		BackendState:          make(map[string]BypassRuleSetBackendState, 2),
	}
	if i.localTCEnabled() && i.tcBackend() != nil {
		localState.BackendState["TC"] = BypassRuleSetBackendState{Version: i.bypassRuleSetTC.version, Known: i.bypassRuleSetTC.known}
	}
	if i.cgroupBackendInstance() != nil {
		localState.BackendState["cgroup"] = BypassRuleSetBackendState{Version: i.bypassRuleSetCgroup.version, Known: i.bypassRuleSetCgroup.known}
	}
	sharedState := scopedBypassRuleSetDiagnostics{
		Consistent:            !i.sharedBypassRuleSetInconsistent,
		Pending:               i.sharedBypassRuleSetNeedsRetry,
		PolicyVersion:         i.sharedBypassRuleSetPolicyVersion,
		ExpectedPolicyVersion: i.sharedBypassRuleSetExpectedVersion,
		RetryCount:            i.sharedBypassRuleSetRetryCount,
		BackendState:          make(map[string]BypassRuleSetBackendState, 2),
	}
	if shared := i.sharedRewriteInstance(); shared != nil && shared.sharedBackendInstance() != nil {
		sharedState.BackendState["packet_rewrite"] = BypassRuleSetBackendState{Version: i.bypassRuleSetShared.version, Known: i.bypassRuleSetShared.known}
	}
	if i.sharedSocketAssignEnabled() && i.tcBackend() != nil {
		sharedState.BackendState["TC"] = BypassRuleSetBackendState{Version: i.sharedBypassRuleSetTC.version, Known: i.sharedBypassRuleSetTC.known}
	}
	diagnostics.LocalBypassRuleSet = localState
	diagnostics.SharedBypassRuleSet = sharedState
	i.bypassRuleSetAccess.Unlock()

	diagnostics.UDPSessionCount = i.udpClientTable.count()
	diagnostics.UDPNAT.add(i.udpNat.diagnostics())
	if shared := i.sharedRewriteInstance(); shared != nil {
		diagnostics.UDPSessionCount += shared.sharedUDPClientTable.count()
		diagnostics.UDPNAT.add(shared.udpNat.diagnostics())
	}
	if backend := i.cgroupBackendInstance(); backend != nil {
		if drops, err := backend.UDPReleaseNotificationDrops(); err == nil {
			diagnostics.UDPNAT.ReleaseNotificationDrops = drops
		}
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
		// These counters were added after the original alpha.9 library API.
		// Use an optional capability interface so a sing-box binary built with
		// the older library remains loadable during the dependency update window.
		if stats, ok := any(sharedRewriteBackend).(sharedNetworkFragmentPassStats); ok {
			if passes, err := stats.IngressFragmentPasses(); err == nil {
				diagnostics.Counters.SharedIngressFragmentPasses = passes
			}
			if passes, err := stats.EgressFragmentPasses(); err == nil {
				diagnostics.Counters.SharedEgressFragmentPasses = passes
			}
		}
	}
	// fakeip_icmp can be hosted independently by the TC backend (local TC,
	// shared socket_assign) and by the shared packet-rewrite backend at the
	// same time -- each loads its own copy of the object -- so their counts
	// are summed rather than one overwriting the other.
	addFakeIPICMPCounters(&diagnostics.Counters, i.tcBackend(), sharedRewriteBackend)
	if tcBackend := i.tcBackend(); tcBackend != nil {
		if stats, err := tcBackend.Stats(); err == nil {
			diagnostics.Counters.TCSocketLookupFailures = stats.SocketLookupFailures
			diagnostics.Counters.TCSKAssignFailures = stats.SKAssignFailures
			diagnostics.Counters.TCAssignmentUpdateFailures = stats.AssignmentUpdateFailures
			diagnostics.Counters.TCLocalFragmentPasses = stats.LocalFragmentPasses
			diagnostics.Counters.TCSharedFragmentPasses = stats.SharedFragmentPasses
		}
	}

	diagnostics.State = deriveDiagnosticsState(diagnostics)
	return diagnostics
}

type sharedNetworkFragmentPassStats interface {
	IngressFragmentPasses() (uint64, error)
	EgressFragmentPasses() (uint64, error)
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
	if d.RecoveryUnrecoverable || !d.LocalBypassRuleSet.Consistent || !d.SharedBypassRuleSet.Consistent {
		return EBPFDiagnosticsStateNeedsAttention
	}
	if d.LocalEnabled && !attachmentHasRole(d.Attachments, "local") {
		return EBPFDiagnosticsStateWaitingForInterface
	}
	if d.SharedEnabled && !attachmentHasRole(d.Attachments, "shared") {
		return EBPFDiagnosticsStateWaitingForInterface
	}
	if d.RecoveryPending || d.LocalBypassRuleSet.Pending || d.SharedBypassRuleSet.Pending {
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
	if d.TCBackendMode != "" {
		lines = append(lines, fmt.Sprintf(
			"TC runtime: backend=%s listener=%s attachment=%s delivery=%s#%d mark=%d table=%d priority=%d attachments=%d retired_attachments=%d retired_deliveries=%d health=%s generation=%d",
			d.TCBackendMode, d.TCListenerLookupMode, d.TCAttachmentMode,
			d.TCDeliveryInterface, d.TCDeliveryInterfaceIndex, d.TCRoutingMark,
			d.TCRoutingTable, d.TCRoutingPriority, d.TCAttachmentCount,
			d.TCRetiredAttachmentCount, d.TCRetiredDeliveryCount, d.TCHealthStatus,
			d.TCNetworkGeneration,
		))
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
	lines = append(lines, fmt.Sprintf("local.bypass_rule_set: consistent=%t pending=%t version=%d", d.LocalBypassRuleSet.Consistent, d.LocalBypassRuleSet.Pending, d.LocalBypassRuleSet.PolicyVersion))
	lines = append(lines, fmt.Sprintf("shared.bypass_rule_set: consistent=%t pending=%t version=%d", d.SharedBypassRuleSet.Consistent, d.SharedBypassRuleSet.Pending, d.SharedBypassRuleSet.PolicyVersion))
	lines = append(lines, fmt.Sprintf("UDP sessions: %d", d.UDPSessionCount))
	lines = append(lines, fmt.Sprintf(
		"UDP NAT: active=%d created=%d capacity_evictions=%d queue_drops=%d socket_release_events=%d socket_release_matched=%d pending_release_capacity_rejected=%d release_notification_drops=%d",
		d.UDPNAT.ActiveSessions, d.UDPNAT.CreatedSessions, d.UDPNAT.CapacityEvictions, d.UDPNAT.QueueDrops,
		d.UDPNAT.SocketReleaseEvents, d.UDPNAT.SocketReleaseMatched,
		d.UDPNAT.PendingReleaseCapacityRejected, d.UDPNAT.ReleaseNotificationDrops,
	))
	lines = append(lines, fmt.Sprintf(
		"UDP reply sockets: count=%d peak=%d evicted=%d capacity_rejected=%d",
		d.UDPReplySockets.Count, d.UDPReplySockets.Peak, d.UDPReplySockets.Evicted, d.UDPReplySockets.CapacityRejected,
	))
	lines = append(lines, fmt.Sprintf(
		"Counters: assignment_lookup_failures=%d tc_socket_lookup_failures=%d tc_sk_assign_failures=%d tc_assignment_update_failures=%d tc_local_fragment_passes=%d tc_shared_fragment_passes=%d token_reservation_failures=%d rewrite_failures=%d "+
			"shared_ingress_fragment_passes=%d shared_egress_fragment_passes=%d "+
			"shared_reconcile_failures=%d recovery_attempts=%d recovery_successes=%d recovery_failures=%d",
		d.Counters.AssignmentLookupFailures, d.Counters.TCSocketLookupFailures, d.Counters.TCSKAssignFailures, d.Counters.TCAssignmentUpdateFailures,
		d.Counters.TCLocalFragmentPasses, d.Counters.TCSharedFragmentPasses,
		d.Counters.TokenReservationFailures, d.Counters.RewriteFailures,
		d.Counters.SharedIngressFragmentPasses, d.Counters.SharedEgressFragmentPasses,
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
// summary can never say something the API diagnostics would disagree
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
