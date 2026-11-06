//go:build with_ebpf && (linux || android)

package ebpf

import (
	"sort"
	"time"

	"github.com/sagernet/sing-box/adapter"

	commonEBPF "github.com/CHIZI-0618/sing-ebpf"
)

// inboundRuntimeSnapshot captures resource owners while the inbound lifecycle
// lock is held. Diagnostics then observes a stable set of runtime pointers
// without holding lifecycle locks while querying kernel-backed state.
type inboundRuntimeSnapshot struct {
	selfBypass        *commonEBPF.SelfBypass
	cgroupBackend     *commonEBPF.CgroupBackend
	tcDataPlane       tcRuntime
	sharedRewrite     *sharedRewrite
	networkGeneration uint64
}

func (i *Inbound) runtimeSnapshotLocked() inboundRuntimeSnapshot {
	return inboundRuntimeSnapshot{
		selfBypass:        i.selfBypass,
		cgroupBackend:     i.cgroupBackendInstance(),
		tcDataPlane:       i.tcDataPlaneInstance(),
		sharedRewrite:     i.sharedRewriteInstance(),
		networkGeneration: i.networkGeneration,
	}
}

func (s inboundRuntimeSnapshot) tcBackend() *commonEBPF.TCBackend {
	if s.tcDataPlane == nil {
		return nil
	}
	return s.tcDataPlane.Backend()
}

func (i *Inbound) Diagnostics() EBPFDiagnostics {
	i.lifecycleAccess.Lock()
	defer i.lifecycleAccess.Unlock()
	return i.diagnosticsLocked()
}

// diagnosticsLocked builds a snapshot while the caller owns lifecycleAccess.
// Keeping this separate lets startup emit its summary without recursively
// acquiring the lifecycle lock it already holds.
func (i *Inbound) diagnosticsLocked() EBPFDiagnostics {
	// Keep runtime owners alive while their kernel-backed diagnostics are read.
	runtime := i.runtimeSnapshotLocked()
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
		if runtime.selfBypass != nil {
			selfBypass := runtime.selfBypass.Diagnostics()
			diagnostics.LocalSelfBypassDecision = selfBypass.DecisionBackend
			diagnostics.LocalSelfBypassProducer = selfBypass.ProducerBackend
			diagnostics.LocalSelfBypassVisibility = selfBypass.VisibilityBackend
			diagnostics.LocalSelfBypassCleanup = selfBypass.CleanupBackend
			diagnostics.LocalSelfBypassAttachment = selfBypass.AttachmentBackend
			diagnostics.LocalSelfBypassReclaim = selfBypass.ReclaimBackend
			diagnostics.LocalSelfBypassFallbackReason = selfBypass.FallbackReason
			diagnostics.LocalSelfBypassReclaimAttempts = selfBypass.ReclaimAttempts
			diagnostics.LocalSelfBypassReclaimedSockets = selfBypass.ReclaimedSockets
			diagnostics.LocalSelfBypassReclaimFailures = selfBypass.ReclaimFailures
			diagnostics.LocalSelfBypassStorageFailures = selfBypass.StorageWriteFails
			diagnostics.LocalSelfBypassCookieFallbacks = selfBypass.CookieFallbacks
			if selfBypass.ReclaimLastAt != 0 {
				lastAt := time.Unix(0, selfBypass.ReclaimLastAt)
				diagnostics.LocalSelfBypassReclaimLastAt = &lastAt
			}
		}
	}
	if backend := runtime.cgroupBackend; backend != nil && !backend.IsClosed() {
		diagnostics.LocalCgroupAttachMode = backend.AttachMode()
		diagnostics.LocalUDPCleanupMode = backend.UDPCleanupMode()
		diagnostics.LocalUDPUserspaceCleanupMode = backend.UDPUserspaceCleanupMode()
		diagnostics.LocalUDPStorageMode = backend.UDPStorageMode()
		diagnostics.LocalUDPTimeMode = backend.UDPTimeMode()
		udpState := backend.UDPStateDiagnostics()
		diagnostics.LocalUDPState = udpState.State
		diagnostics.LocalUDPRecoveryMode = udpState.RecoveryMode
		diagnostics.LocalUDPMapPressure = udpState.MapPressure
		diagnostics.LocalUDPNetworkGeneration = udpState.NetworkGeneration
		if releasePath, ok := any(backend).(udpReleasePathDiagnostics); ok {
			diagnostics.LocalUDPReleaseObserver,
				diagnostics.LocalUDPReleaseFallbackReason,
				diagnostics.LocalUDPReleaseProgram = releasePath.UDPReleasePathDiagnostics()
		}
	}
	if i.sharedEnabled {
		diagnostics.SharedDataPlane = i.sharedDataPlane
	}

	tcDataPlane := runtime.tcDataPlane
	if tcDataPlane != nil {
		diagnostics.Attachments = append(diagnostics.Attachments, tcDataPlane.AttachmentDiagnostics()...)
		tc := tcDataPlane.TCDiagnostics()
		diagnostics.TCListenerLookupMode = tc.ListenerLookupMode
		diagnostics.TCAttachmentMode = tc.AttachmentMode
		diagnostics.TCDeliveryInterface = tc.NetworkInfo.DeliveryInterface
		diagnostics.TCNetworkNamespace = tc.NetworkInfo.Namespace
		diagnostics.TCDeliveryInterfaceIndex = tc.NetworkInfo.DeliveryInterfaceIndex
		diagnostics.TCRoutingMark = tc.NetworkInfo.RoutingMark
		diagnostics.TCRoutingTable = tc.NetworkInfo.RoutingTable
		diagnostics.TCRoutingPriority = tc.NetworkInfo.RoutingPriority
		diagnostics.TCRoutingSlot = tc.NetworkInfo.RoutingSlot
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
	if shared := runtime.sharedRewrite; shared != nil {
		if sharedDataPlane := shared.dataPlaneInstance(); sharedDataPlane != nil {
			diagnostics.Attachments = append(diagnostics.Attachments, sharedDataPlane.AttachmentDiagnostics()...)
		}
	}
	if i.localCgroupEnabled() {
		if backend := runtime.cgroupBackend; backend != nil && !backend.IsClosed() {
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
	diagnostics.WaitingRoles, diagnostics.WaitingInterfaces = i.waitingAttachmentDiagnostics(diagnostics.Attachments)

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
	if shared := runtime.sharedRewrite; shared != nil {
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
	diagnostics.TCNetworkGeneration = runtime.networkGeneration
	diagnostics.TCAssignmentSweepScanned = i.tcAssignmentSweepScanned.Load()
	diagnostics.TCAssignmentSweepRemoved = i.tcAssignmentSweepRemoved.Load()
	diagnostics.TCAssignmentSweepMissing = i.tcAssignmentSweepMissing.Load()
	diagnostics.TCAssignmentSweepSuperseded = i.tcAssignmentSweepSuperseded.Load()
	diagnostics.TCAssignmentSweepInFlight = i.tcAssignmentSweepInFlight.Load()
	diagnostics.TCAssignmentSweepComplete = i.tcAssignmentSweepComplete.Load()
	diagnostics.TCAssignmentSweepEntries = i.tcAssignmentSweepEntries.Load()
	diagnostics.TCReturnSweepEntries = i.tcReturnSweepEntries.Load()
	diagnostics.TCReturnSweepCapacity = i.tcReturnSweepCapacity.Load()
	diagnostics.TCReturnSweepScanned = i.tcReturnSweepScanned.Load()
	diagnostics.TCReturnSweepRemoved = i.tcReturnSweepRemoved.Load()
	diagnostics.TCAssignmentSweepUsageKnown = i.tcAssignmentSweepUsageKnown.Load()
	diagnostics.TCReturnSweepUsageKnown = i.tcReturnSweepUsageKnown.Load()
	diagnostics.TCAssignmentSweepFailureMap, _ = i.tcAssignmentSweepFailureMap.Load().(string)
	diagnostics.TCAssignmentSweepCapacity = i.tcAssignmentSweepCapacity.Load()
	diagnostics.TCAssignmentSweepPressure = i.tcAssignmentSweepPressure.Load()
	diagnostics.TCAssignmentSweepRuns = i.tcAssignmentSweepRuns.Load()
	diagnostics.TCAssignmentSweepPartial = i.tcAssignmentSweepPartial.Load()
	if failure, ok := i.tcAssignmentSweepFailure.Load().(string); ok {
		diagnostics.TCAssignmentSweepFailure = failure
	}
	if at := i.tcAssignmentSweepLastAt.Load(); at != 0 {
		t := time.Unix(0, at)
		diagnostics.TCAssignmentSweepLastAt = &t
	}
	if at := i.tcAssignmentSweepPartialAt.Load(); at != 0 {
		t := time.Unix(0, at)
		diagnostics.TCAssignmentSweepPartialAt = &t
	}
	diagnostics.CgroupRecoveryQueueOverflows = i.cgroupRecoveryQueueOverflows.Load()
	if at := i.cgroupRecoveryQueueOverflowAt.Load(); at != 0 {
		t := time.Unix(0, at)
		diagnostics.CgroupRecoveryQueueOverflowAt = &t
	}
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
		Consistent:            !i.localBypassRules.inconsistent,
		Pending:               i.localBypassRules.needsRetry,
		PolicyVersion:         i.localBypassRules.policyVersion,
		ExpectedPolicyVersion: i.localBypassRules.expectedVersion,
		RetryCount:            i.localBypassRules.retryCount,
		BackendState:          make(map[string]BypassRuleSetBackendState, 2),
	}
	if i.localSocketAssignEnabled() && runtime.tcBackend() != nil {
		localState.BackendState["TC"] = BypassRuleSetBackendState{Version: i.localBypassRules.tc.version, Known: i.localBypassRules.tc.known}
	}
	if runtime.cgroupBackend != nil {
		localState.BackendState["cgroup"] = BypassRuleSetBackendState{Version: i.localBypassRules.cgroup.version, Known: i.localBypassRules.cgroup.known}
	}
	sharedState := scopedBypassRuleSetDiagnostics{
		Consistent:            !i.sharedBypassRules.inconsistent,
		Pending:               i.sharedBypassRules.needsRetry,
		PolicyVersion:         i.sharedBypassRules.policyVersion,
		ExpectedPolicyVersion: i.sharedBypassRules.expectedVersion,
		RetryCount:            i.sharedBypassRules.retryCount,
		BackendState:          make(map[string]BypassRuleSetBackendState, 2),
	}
	if shared := runtime.sharedRewrite; shared != nil && shared.sharedBackendInstance() != nil {
		sharedState.BackendState["packet_rewrite"] = BypassRuleSetBackendState{Version: i.sharedBypassRules.shared.version, Known: i.sharedBypassRules.shared.known}
	}
	if i.sharedSocketAssignEnabled() && runtime.tcBackend() != nil {
		sharedState.BackendState["TC"] = BypassRuleSetBackendState{Version: i.sharedBypassRules.tc.version, Known: i.sharedBypassRules.tc.known}
	}
	diagnostics.LocalBypassRuleSet = localState
	diagnostics.SharedBypassRuleSet = sharedState
	diagnostics.PolicyEpoch = EBPFPolicyEpochDiagnostics{
		LocalConfirmed:  localState.PolicyVersion,
		LocalExpected:   localState.ExpectedPolicyVersion,
		SharedConfirmed: sharedState.PolicyVersion,
		SharedExpected:  sharedState.ExpectedPolicyVersion,
		Converged: localState.Consistent && sharedState.Consistent &&
			!localState.Pending && !sharedState.Pending &&
			localState.PolicyVersion == localState.ExpectedPolicyVersion &&
			sharedState.PolicyVersion == sharedState.ExpectedPolicyVersion,
	}
	i.bypassRuleSetAccess.Unlock()

	diagnostics.UDPSessionCount = i.udpClientTable.count()
	diagnostics.UDPNAT.add(i.udpNat.diagnostics())
	if shared := runtime.sharedRewrite; shared != nil {
		diagnostics.UDPSessionCount += shared.sharedUDPClientTable.count()
		diagnostics.UDPNAT.add(shared.udpNat.diagnostics())
	}
	if backend := runtime.cgroupBackend; backend != nil {
		if drops, err := backend.UDPReleaseNotificationDrops(); err == nil {
			diagnostics.UDPNAT.ReleaseNotificationDrops = drops
		}
		readStat := func(stat commonEBPF.CgroupUDPStat) uint64 {
			value, err := backend.UDPReleaseStat(stat)
			if err != nil {
				return 0
			}
			return value
		}
		diagnostics.UDPNAT.RedirectAdmissionFailures = readStat(commonEBPF.CgroupUDPStatTCPRedirectFailure) + readStat(commonEBPF.CgroupUDPStatUDPRedirectFailure)
		diagnostics.UDPNAT.UDPTokenAdmissionFailures = readStat(commonEBPF.CgroupUDPStatUDPTokenFailure)
		diagnostics.UDPNAT.UDPTokenReverseFailures = readStat(commonEBPF.CgroupUDPStatUDPTokenReverseFailure)
		diagnostics.UDPNAT.UDPPeerAdmissionFailures = readStat(commonEBPF.CgroupUDPStatUDPPeerFailure)
		diagnostics.UDPNAT.TCPPeerAdmissionFailures = readStat(commonEBPF.CgroupUDPStatTCPPeerFailure)
		diagnostics.UDPNAT.UDPRecoveryAdmissionFailures = readStat(commonEBPF.CgroupUDPStatUDPRecoveryFailure)
	}
	diagnostics.UDPReplySockets = i.udpReplySockets.snapshot()

	diagnostics.Counters = i.counters.snapshot()
	var sharedRewriteBackend *commonEBPF.SharedPacketRewriteBackend
	if shared := runtime.sharedRewrite; shared != nil {
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
	addFakeIPICMPCounters(&diagnostics.Counters, runtime.tcBackend(), sharedRewriteBackend)
	if tcBackend := runtime.tcBackend(); tcBackend != nil {
		if stats, err := tcBackend.Stats(); err == nil {
			diagnostics.Counters.TCSocketLookupFailures = stats.SocketLookupFailures
			diagnostics.Counters.TCSKAssignFailures = stats.SKAssignFailures
			diagnostics.Counters.TCAssignmentUpdateFailures = stats.AssignmentUpdateFailures
			diagnostics.Counters.TCReturnUpdateFailures = stats.ReturnUpdateFailures
			diagnostics.Counters.TCReturnConflicts = stats.ReturnConflicts
			diagnostics.Counters.TCReturnLookupFailures = stats.ReturnLookupFailures
			diagnostics.Counters.TCLocalFragmentPasses = stats.LocalFragmentPasses
			diagnostics.Counters.TCSharedFragmentPasses = stats.SharedFragmentPasses
		}
	}

	diagnostics.State = deriveDiagnosticsState(diagnostics)
	return diagnostics
}

func (i *Inbound) waitingAttachmentDiagnostics(attachments []EBPFAttachmentDiagnostics) ([]string, []string) {
	roles := make([]string, 0, 2)
	interfaces := make([]string, 0, 2)
	add := func(role, interfaceName string) {
		roleKnown := false
		for _, existing := range roles {
			if existing == role {
				roleKnown = true
				break
			}
		}
		if !roleKnown {
			roles = append(roles, role)
		}
		if interfaceName != "" {
			for _, existing := range interfaces {
				if existing == interfaceName {
					return
				}
			}
			interfaces = append(interfaces, interfaceName)
		}
	}
	if i.localSocketAssignEnabled() && !attachmentHasRole(attachments, "local") {
		defaultInterface := i.monitoredDefaultInterfaceName()
		if defaultInterface == "" {
			defaultInterface = "default"
		}
		add("local", defaultInterface)
	}
	if i.sharedEnabled && !attachmentHasRole(attachments, "shared") {
		configured := activeSharedInterfaces(i.sharedOptions.Interface, i.monitoredDefaultInterfaceName(), i.sharedOptions.DefaultInterface)
		if len(configured) == 0 {
			add("shared", "configured interface")
		} else {
			for _, interfaceName := range configured {
				if !attachmentHasInterface(attachments, interfaceName, "shared") {
					add("shared", interfaceName)
				}
			}
		}
	}
	return roles, interfaces
}

func attachmentHasInterface(attachments []EBPFAttachmentDiagnostics, interfaceName, role string) bool {
	for _, attachment := range attachments {
		if attachment.InterfaceName == interfaceName && (attachment.Role == role || attachment.Role == "local+shared") {
			return true
		}
	}
	return false
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
	if d.LocalEnabled && d.LocalDataPlane == "cgroup" && d.LocalCgroupAttachMode == "" {
		return EBPFDiagnosticsStateNeedsAttention
	}
	if d.LocalEnabled && d.LocalDataPlane != "cgroup" && !attachmentHasRole(d.Attachments, "local") {
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
