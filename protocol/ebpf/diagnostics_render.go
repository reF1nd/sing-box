//go:build with_ebpf && (linux || android)

package ebpf

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
)

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
	if len(d.WaitingRoles) > 0 {
		lines = append(lines, fmt.Sprintf("Waiting paths: %s", strings.Join(d.WaitingRoles, ", ")))
	}
	if len(d.WaitingInterfaces) > 0 {
		lines = append(lines, fmt.Sprintf("Waiting interfaces: %s", strings.Join(d.WaitingInterfaces, ", ")))
	}
	if d.TCBackendMode != "" {
		if d.TCNetworkNamespace != "" {
			lines = append(lines, "TC socket namespace: "+d.TCNetworkNamespace)
		}
		lines = append(lines, fmt.Sprintf(
			"TC runtime: backend=%s listener=%s attachment=%s delivery=%s#%d mark=%d table=%d priority=%d slot=%d attachments=%d retired_attachments=%d retired_deliveries=%d health=%s generation=%d",
			d.TCBackendMode, d.TCListenerLookupMode, d.TCAttachmentMode,
			d.TCDeliveryInterface, d.TCDeliveryInterfaceIndex, d.TCRoutingMark,
			d.TCRoutingTable, d.TCRoutingPriority, d.TCRoutingSlot, d.TCAttachmentCount,
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
				"  %s: role=%s mechanism=%s framing=%s slot=%d fakeip_icmp=%t",
				attachment.InterfaceName, attachment.Role, attachment.Mechanism, framing, attachment.Slot, attachment.ICMPEchoReply,
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
	lines = append(lines, fmt.Sprintf("policy_epoch: local=%d/%d shared=%d/%d converged=%t", d.PolicyEpoch.LocalConfirmed, d.PolicyEpoch.LocalExpected, d.PolicyEpoch.SharedConfirmed, d.PolicyEpoch.SharedExpected, d.PolicyEpoch.Converged))
	lines = append(lines, fmt.Sprintf("UDP sessions: %d", d.UDPSessionCount))
	lines = append(lines, fmt.Sprintf(
		"UDP NAT: active=%d created=%d capacity_evictions=%d queue_drops=%d socket_release_events=%d socket_release_matched=%d pending_release_capacity_rejected=%d release_notification_drops=%d redirect_admission_failures=%d udp_token_admission_failures=%d udp_token_reverse_failures=%d udp_peer_admission_failures=%d tcp_peer_admission_failures=%d udp_recovery_admission_failures=%d",
		d.UDPNAT.ActiveSessions, d.UDPNAT.CreatedSessions, d.UDPNAT.CapacityEvictions, d.UDPNAT.QueueDrops,
		d.UDPNAT.SocketReleaseEvents, d.UDPNAT.SocketReleaseMatched,
		d.UDPNAT.PendingReleaseCapacityRejected, d.UDPNAT.ReleaseNotificationDrops,
		d.UDPNAT.RedirectAdmissionFailures, d.UDPNAT.UDPTokenAdmissionFailures,
		d.UDPNAT.UDPTokenReverseFailures, d.UDPNAT.UDPPeerAdmissionFailures,
		d.UDPNAT.TCPPeerAdmissionFailures, d.UDPNAT.UDPRecoveryAdmissionFailures,
	))
	lines = append(lines, fmt.Sprintf(
		"UDP reply sockets: count=%d peak=%d evicted=%d capacity_rejected=%d",
		d.UDPReplySockets.Count, d.UDPReplySockets.Peak, d.UDPReplySockets.Evicted, d.UDPReplySockets.CapacityRejected,
	))
	lines = append(lines, fmt.Sprintf(
		"Counters: assignment_lookup_failures=%d tc_socket_lookup_failures=%d tc_sk_assign_failures=%d tc_assignment_update_failures=%d tc_return_update_failures=%d tc_return_conflicts=%d tc_return_lookup_failures=%d tc_local_fragment_passes=%d tc_shared_fragment_passes=%d token_reservation_failures=%d rewrite_failures=%d "+
			"shared_ingress_fragment_passes=%d shared_egress_fragment_passes=%d "+
			"shared_reconcile_failures=%d recovery_attempts=%d recovery_successes=%d recovery_failures=%d",
		d.Counters.AssignmentLookupFailures, d.Counters.TCSocketLookupFailures, d.Counters.TCSKAssignFailures, d.Counters.TCAssignmentUpdateFailures,
		d.Counters.TCReturnUpdateFailures, d.Counters.TCReturnConflicts, d.Counters.TCReturnLookupFailures,
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
// visible Info statement of which paths are enabled, what each
// actually mounted as (interface and mechanism, not just the configured
// data plane -- a config can ask for TCX and still land on clsact), which
// configured paths have no interface to attach to yet, and which
// attachments fakeip_icmp actually covers. It is built from the same
// Diagnostics this inbound already computes for external queries, so the
// summary can never say something the API diagnostics would disagree
// with a moment later.
//
// The detailed tc_runtime and cgroup_runtime events remain Debug-level and
// are emitted separately by startInbound. This Info event is intentionally a
// small lifecycle summary suitable for normal operation logs.
func (i *Inbound) logStartupSummary() {
	i.lifecycleAccess.Lock()
	defer i.lifecycleAccess.Unlock()
	i.logStartupSummaryLocked()
}

func (i *Inbound) logStartupSummaryLocked() {
	diagnostics := i.diagnosticsLocked()

	paths := make([]string, 0, 2)
	if diagnostics.LocalEnabled {
		paths = append(paths, "local="+diagnostics.LocalDataPlane)
	}
	if diagnostics.SharedEnabled {
		paths = append(paths, "shared="+diagnostics.SharedDataPlane)
	}
	if paths == nil {
		paths = []string{}
	}
	activeAttachments := make([]ebpfAttachmentLogSummary, 0, len(diagnostics.Attachments))
	for _, attachment := range diagnostics.Attachments {
		activeAttachments = append(activeAttachments, ebpfAttachmentLogSummary{
			Interface: attachment.InterfaceName,
			Role:      attachment.Role,
			Mechanism: attachment.Mechanism,
		})
	}

	waiting := diagnostics.WaitingRoles
	if waiting == nil {
		waiting = []string{}
	}
	waitingInterfaces := diagnostics.WaitingInterfaces
	if waitingInterfaces == nil {
		waitingInterfaces = []string{}
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

	i.logger.Info("eBPF ", ebpfStructuredEvent("inbound_start", map[string]any{
		"state":              diagnostics.State,
		"configured_paths":   paths,
		"active_attachments": activeAttachments,
		"waiting_paths":      waiting,
		"waiting_interfaces": waitingInterfaces,
		"fakeip_icmp":        fakeIPICMPSummary,
	}))
}
