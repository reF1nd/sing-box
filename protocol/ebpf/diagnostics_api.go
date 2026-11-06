//go:build with_ebpf && (linux || android)

package ebpf

import (
	"time"

	"github.com/sagernet/sing-box/adapter"

	commonEBPF "github.com/CHIZI-0618/sing-ebpf"
)

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
			Slot:           attachment.Slot,
		})
	}
	result := adapter.EBPFRuntimeDiagnostics{
		SchemaVersion:                   diagnostics.SchemaVersion,
		ObservedAt:                      diagnostics.ObservedAt,
		Tag:                             diagnostics.Tag,
		State:                           diagnostics.State,
		LocalEnabled:                    diagnostics.LocalEnabled,
		LocalDataPlane:                  diagnostics.LocalDataPlane,
		LocalCgroupAttachMode:           diagnostics.LocalCgroupAttachMode,
		LocalSelfBypassDecision:         diagnostics.LocalSelfBypassDecision,
		LocalSelfBypassProducer:         diagnostics.LocalSelfBypassProducer,
		LocalSelfBypassVisibility:       diagnostics.LocalSelfBypassVisibility,
		LocalSelfBypassCleanup:          diagnostics.LocalSelfBypassCleanup,
		LocalSelfBypassReclaim:          diagnostics.LocalSelfBypassReclaim,
		LocalSelfBypassAttachment:       diagnostics.LocalSelfBypassAttachment,
		LocalSelfBypassFallbackReason:   diagnostics.LocalSelfBypassFallbackReason,
		LocalSelfBypassReclaimAttempts:  diagnostics.LocalSelfBypassReclaimAttempts,
		LocalSelfBypassReclaimedSockets: diagnostics.LocalSelfBypassReclaimedSockets,
		LocalSelfBypassReclaimFailures:  diagnostics.LocalSelfBypassReclaimFailures,
		LocalSelfBypassStorageFailures:  diagnostics.LocalSelfBypassStorageFailures,
		LocalSelfBypassCookieFallbacks:  diagnostics.LocalSelfBypassCookieFallbacks,
		LocalUDPCleanupMode:             diagnostics.LocalUDPCleanupMode,
		LocalUDPUserspaceCleanupMode:    diagnostics.LocalUDPUserspaceCleanupMode,
		LocalUDPStorageMode:             diagnostics.LocalUDPStorageMode,
		LocalUDPTimeMode:                diagnostics.LocalUDPTimeMode,
		LocalUDPState:                   diagnostics.LocalUDPState,
		LocalUDPRecoveryMode:            diagnostics.LocalUDPRecoveryMode,
		LocalUDPMapPressure:             diagnostics.LocalUDPMapPressure,
		LocalUDPNetworkGeneration:       diagnostics.LocalUDPNetworkGeneration,
		LocalUDPReleaseObserver:         diagnostics.LocalUDPReleaseObserver,
		LocalUDPReleaseFallbackReason:   diagnostics.LocalUDPReleaseFallbackReason,
		LocalUDPReleaseProgram:          diagnostics.LocalUDPReleaseProgram,
		SharedEnabled:                   diagnostics.SharedEnabled,
		SharedDataPlane:                 diagnostics.SharedDataPlane,
		FakeIPICMPReply:                 diagnostics.FakeIPICMPReply,
		TCBackendMode:                   diagnostics.TCBackendMode,
		TCListenerLookupMode:            diagnostics.TCListenerLookupMode,
		TCAttachmentMode:                diagnostics.TCAttachmentMode,
		TCDeliveryInterface:             diagnostics.TCDeliveryInterface,
		TCNetworkNamespace:              diagnostics.TCNetworkNamespace,
		TCDeliveryInterfaceIndex:        diagnostics.TCDeliveryInterfaceIndex,
		TCRoutingMark:                   diagnostics.TCRoutingMark,
		TCRoutingTable:                  diagnostics.TCRoutingTable,
		TCRoutingPriority:               diagnostics.TCRoutingPriority,
		TCRoutingSlot:                   diagnostics.TCRoutingSlot,
		TCAttachmentCount:               diagnostics.TCAttachmentCount,
		TCRetiredAttachmentCount:        diagnostics.TCRetiredAttachmentCount,
		TCRetiredDeliveryCount:          diagnostics.TCRetiredDeliveryCount,
		TCRequiresRebuild:               diagnostics.TCRequiresRebuild,
		TCHealthStatus:                  diagnostics.TCHealthStatus,
		TCLastHealthCheckAt:             diagnostics.TCLastHealthCheckAt,
		TCLastReconcileAt:               diagnostics.TCLastReconcileAt,
		TCNetworkGeneration:             diagnostics.TCNetworkGeneration,
		TCReturnSweepEntries:            diagnostics.TCReturnSweepEntries,
		TCReturnSweepCapacity:           diagnostics.TCReturnSweepCapacity,
		TCReturnSweepScanned:            diagnostics.TCReturnSweepScanned,
		TCReturnSweepRemoved:            diagnostics.TCReturnSweepRemoved,
		TCAssignmentSweepUsageKnown:     diagnostics.TCAssignmentSweepUsageKnown,
		TCReturnSweepUsageKnown:         diagnostics.TCReturnSweepUsageKnown,
		TCAssignmentSweepFailureMap:     diagnostics.TCAssignmentSweepFailureMap,
		TCAssignmentSweepScanned:        diagnostics.TCAssignmentSweepScanned,
		TCAssignmentSweepRemoved:        diagnostics.TCAssignmentSweepRemoved,
		TCAssignmentSweepMissing:        diagnostics.TCAssignmentSweepMissing,
		TCAssignmentSweepSuperseded:     diagnostics.TCAssignmentSweepSuperseded,
		TCAssignmentSweepInFlight:       diagnostics.TCAssignmentSweepInFlight,
		TCAssignmentSweepComplete:       diagnostics.TCAssignmentSweepComplete,
		TCAssignmentSweepEntries:        diagnostics.TCAssignmentSweepEntries,
		TCAssignmentSweepCapacity:       diagnostics.TCAssignmentSweepCapacity,
		TCAssignmentSweepPressure:       diagnostics.TCAssignmentSweepPressure,
		TCAssignmentSweepRuns:           diagnostics.TCAssignmentSweepRuns,
		TCAssignmentSweepPartial:        diagnostics.TCAssignmentSweepPartial,
		TCAssignmentSweepFailure:        diagnostics.TCAssignmentSweepFailure,
		TCAssignmentSweepLastAt:         diagnostics.TCAssignmentSweepLastAt,
		TCAssignmentSweepPartialAt:      diagnostics.TCAssignmentSweepPartialAt,
		CgroupRecoveryQueueOverflows:    diagnostics.CgroupRecoveryQueueOverflows,
		CgroupRecoveryQueueOverflowAt:   diagnostics.CgroupRecoveryQueueOverflowAt,
		WaitingRoles:                    append([]string(nil), diagnostics.WaitingRoles...),
		WaitingInterfaces:               append([]string(nil), diagnostics.WaitingInterfaces...),
		Attachments:                     attachments,
		LastError:                       diagnostics.LastError,
		LastErrorAt:                     diagnostics.LastErrorAt,
		LastRecoveryAt:                  diagnostics.LastRecoveryAt,
		RecoveryPending:                 diagnostics.RecoveryPending,
		RecoveryUnrecoverable:           diagnostics.RecoveryUnrecoverable,
		NextRetryAt:                     diagnostics.NextRetryAt,
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
		PolicyEpoch: adapter.EBPFPolicyEpochDiagnostics{
			LocalConfirmed:  diagnostics.PolicyEpoch.LocalConfirmed,
			LocalExpected:   diagnostics.PolicyEpoch.LocalExpected,
			SharedConfirmed: diagnostics.PolicyEpoch.SharedConfirmed,
			SharedExpected:  diagnostics.PolicyEpoch.SharedExpected,
			Converged:       diagnostics.PolicyEpoch.Converged,
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
			RedirectAdmissionFailures:      diagnostics.UDPNAT.RedirectAdmissionFailures,
			UDPTokenAdmissionFailures:      diagnostics.UDPNAT.UDPTokenAdmissionFailures,
			UDPTokenReverseFailures:        diagnostics.UDPNAT.UDPTokenReverseFailures,
			UDPPeerAdmissionFailures:       diagnostics.UDPNAT.UDPPeerAdmissionFailures,
			TCPPeerAdmissionFailures:       diagnostics.UDPNAT.TCPPeerAdmissionFailures,
			UDPRecoveryAdmissionFailures:   diagnostics.UDPNAT.UDPRecoveryAdmissionFailures,
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
			TCReturnUpdateFailures:        diagnostics.Counters.TCReturnUpdateFailures,
			TCReturnConflicts:             diagnostics.Counters.TCReturnConflicts,
			TCReturnLookupFailures:        diagnostics.Counters.TCReturnLookupFailures,
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
	result.LocalSelfBypassReclaimLastAt = diagnostics.LocalSelfBypassReclaimLastAt
	return result
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
	if !i.kernelRuntimeAPIAt.IsZero() && now.Sub(i.kernelRuntimeAPIAt) < 5*time.Second {
		return i.kernelRuntimeAPIValue
	}
	// Snapshot handles while lifecycle ownership is stable, then enumerate only
	// those IDs outside the lifecycle lock.
	i.lifecycleAccess.Lock()
	owners := []commonEBPF.RuntimeResources{
		i.cgroupBackendInstance().RuntimeResources(),
		i.tcBackend().RuntimeResources(),
		i.selfBypass.RuntimeResources(),
	}
	if tracker, ok := i.processTracker.(interface {
		RuntimeResources() commonEBPF.RuntimeResources
	}); ok {
		owners = append(owners, tracker.RuntimeResources())
	}
	if shared := i.sharedRewriteInstance(); shared != nil {
		owners = append(owners, shared.sharedBackendInstance().RuntimeResources())
	}
	i.lifecycleAccess.Unlock()
	diagnostics := kernelRuntimeForAPI(now, commonEBPF.InspectRuntimeResources(owners...))
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
			ID:                uint32(item.ID),
			Name:              item.Name,
			Category:          string(item.Category),
			Type:              item.Type,
			MaxEntries:        item.MaxEntries,
			KeySize:           item.KeySize,
			ValueSize:         item.ValueSize,
			Flags:             item.Flags,
			Entries:           item.Entries,
			Supported:         item.Supported,
			Error:             item.Error,
			Pressure:          item.Pressure,
			OccupancyMode:     item.OccupancyMode,
			EvictionMode:      item.EvictionMode,
			AdmissionCritical: item.AdmissionCritical,
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
