//go:build with_ebpf && (linux || android)

package ebpf

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"

	commonEBPF "github.com/CHIZI-0618/sing-ebpf"
)

type captureLogger struct {
	debugMessages []string
	infoMessages  []string
}

func (l *captureLogger) Trace(args ...any) {}
func (l *captureLogger) Debug(args ...any) {
	var builder strings.Builder
	for _, arg := range args {
		if text, ok := arg.(string); ok {
			builder.WriteString(text)
		}
	}
	l.debugMessages = append(l.debugMessages, builder.String())
}
func (l *captureLogger) Info(args ...any)  { l.infoMessages = append(l.infoMessages, "called") }
func (l *captureLogger) Warn(args ...any)  {}
func (l *captureLogger) Error(args ...any) {}
func (l *captureLogger) Fatal(args ...any) {}
func (l *captureLogger) Panic(args ...any) {}

func (l *captureLogger) TraceContext(context.Context, ...any)        {}
func (l *captureLogger) DebugContext(_ context.Context, args ...any) { l.Debug(args...) }
func (l *captureLogger) InfoContext(ctx context.Context, args ...any) {
	l.Info(args...)
}
func (l *captureLogger) WarnContext(context.Context, ...any)  {}
func (l *captureLogger) ErrorContext(context.Context, ...any) {}
func (l *captureLogger) FatalContext(context.Context, ...any) {}
func (l *captureLogger) PanicContext(context.Context, ...any) {}

// TestDiagnosticsReportsWaitingForInterfaceWhenNothingIsAttachedYet covers
// the state that is not a failure at all: a data plane is configured but no
// matching interface exists yet, so there is nothing to attach to.
func TestDiagnosticsReportsWaitingForInterfaceWhenNothingIsAttachedYet(t *testing.T) {
	inbound := &Inbound{localEnabled: true, localDataPlane: localDataPlaneTC}
	diagnostics := inbound.Diagnostics()
	if diagnostics.SchemaVersion != adapter.EBPFDiagnosticsSchemaVersion || diagnostics.ObservedAt.IsZero() {
		t.Fatalf("diagnostics metadata = version %d at %v, want schema version %d and timestamp", diagnostics.SchemaVersion, diagnostics.ObservedAt, adapter.EBPFDiagnosticsSchemaVersion)
	}
	if diagnostics.State != EBPFDiagnosticsStateWaitingForInterface {
		t.Fatalf("state = %s, want %s", diagnostics.State, EBPFDiagnosticsStateWaitingForInterface)
	}
	if len(diagnostics.Attachments) != 0 {
		t.Fatalf("attachments = %v, want none", diagnostics.Attachments)
	}
}

func TestEBPFDiagnosticsUsesShortRequestDrivenCache(t *testing.T) {
	inbound := &Inbound{localEnabled: true, localDataPlane: localDataPlaneTC}
	first := inbound.EBPFDiagnostics()
	second := inbound.EBPFDiagnostics()
	if !first.ObservedAt.Equal(second.ObservedAt) {
		t.Fatalf("cache miss inside TTL: first=%v second=%v", first.ObservedAt, second.ObservedAt)
	}
	firstRuntime := inbound.EBPFKernelRuntime()
	secondRuntime := inbound.EBPFKernelRuntime()
	if !firstRuntime.ObservedAt.Equal(secondRuntime.ObservedAt) {
		t.Fatalf("kernel runtime cache miss inside TTL: first=%v second=%v", firstRuntime.ObservedAt, secondRuntime.ObservedAt)
	}
}

func TestEBPFDiagnosticsIncludesEffectiveCgroupPaths(t *testing.T) {
	diagnostics := diagnosticsForAPI(EBPFDiagnostics{
		LocalCgroupAttachMode:        "legacy_exclusive",
		LocalUDPCleanupMode:          "lru_fallback",
		LocalUDPUserspaceCleanupMode: "deadline",
		LocalUDPStorageMode:          "socket_storage",
		LocalUDPTimeMode:             "coarse",
	})
	if diagnostics.LocalCgroupAttachMode != "legacy_exclusive" ||
		diagnostics.LocalUDPCleanupMode != "lru_fallback" ||
		diagnostics.LocalUDPUserspaceCleanupMode != "deadline" ||
		diagnostics.LocalUDPStorageMode != "socket_storage" ||
		diagnostics.LocalUDPTimeMode != "coarse" {
		t.Fatalf("effective cgroup paths were not propagated: %+v", diagnostics)
	}
}

func TestEBPFDiagnosticsIncludesEffectiveTCState(t *testing.T) {
	observedHealth := time.Unix(1700000000, 0)
	observedReconcile := observedHealth.Add(time.Second)
	diagnostics := diagnosticsForAPI(EBPFDiagnostics{
		SchemaVersion:            adapter.EBPFDiagnosticsSchemaVersion,
		TCBackendMode:            "socket_assign",
		TCListenerLookupMode:     "sockmap",
		TCAttachmentMode:         "tcx",
		TCDeliveryInterface:      "sb-delivery0",
		TCDeliveryInterfaceIndex: 42,
		TCRoutingMark:            1 << 29,
		TCRoutingTable:           2022,
		TCRoutingPriority:        10000,
		TCAttachmentCount:        2,
		TCRetiredAttachmentCount: 1,
		TCRetiredDeliveryCount:   1,
		TCRequiresRebuild:        false,
		TCHealthStatus:           "attached",
		TCLastHealthCheckAt:      &observedHealth,
		TCLastReconcileAt:        &observedReconcile,
		TCNetworkGeneration:      3,
	})
	if diagnostics.SchemaVersion != 7 || diagnostics.TCBackendMode != "socket_assign" ||
		diagnostics.TCListenerLookupMode != "sockmap" || diagnostics.TCAttachmentMode != "tcx" ||
		diagnostics.TCDeliveryInterfaceIndex != 42 || diagnostics.TCAttachmentCount != 2 ||
		diagnostics.TCNetworkGeneration != 3 || diagnostics.TCLastHealthCheckAt == nil ||
		!diagnostics.TCLastHealthCheckAt.Equal(observedHealth) || diagnostics.TCLastReconcileAt == nil ||
		!diagnostics.TCLastReconcileAt.Equal(observedReconcile) {
		t.Fatalf("effective TC state was not propagated: %+v", diagnostics)
	}
}

func TestEBPFDiagnosticsSchemaVersionIncludesEffectiveRuntimeFields(t *testing.T) {
	if adapter.EBPFDiagnosticsSchemaVersion != 7 {
		t.Fatalf("schema version = %d, want 7 after removing experimental pass counters", adapter.EBPFDiagnosticsSchemaVersion)
	}
	diagnostics := diagnosticsForAPI(EBPFDiagnostics{SchemaVersion: adapter.EBPFDiagnosticsSchemaVersion, LocalCgroupAttachMode: "link_create"})
	if diagnostics.SchemaVersion != 7 {
		t.Fatalf("diagnostics schema version = %d, want 7", diagnostics.SchemaVersion)
	}
}

func TestKernelRuntimeForAPI(t *testing.T) {
	observedAt := time.UnixMilli(1700000000123)
	diagnostics := kernelRuntimeForAPI(observedAt, commonEBPF.RuntimeState{
		Programs: []commonEBPF.RuntimeProgram{{
			ID:       42,
			Name:     "sb_share_ingress",
			MapCount: 2,
		}},
		ProgramsError: errors.New("program enumeration denied"),
		MapOccupancy: commonEBPF.MapOccupancyReport{
			Status: "unknown",
			Maps: []commonEBPF.MapOccupancy{{
				ID: 9, Name: "sb_shared_flows", Type: "LRUHash", MaxEntries: 4096,
				Entries: 3, Supported: true,
			}},
			Error: "map enumeration incomplete",
		},
	})
	if !diagnostics.ObservedAt.Equal(observedAt) || diagnostics.ProgramsError != "program enumeration denied" {
		t.Fatalf("unexpected runtime metadata: %+v", diagnostics)
	}
	if len(diagnostics.Programs) != 1 || diagnostics.Programs[0].ID != 42 || diagnostics.Programs[0].MapCount != 2 {
		t.Fatalf("unexpected programs: %+v", diagnostics.Programs)
	}
	if diagnostics.MapOccupancy.Status != "unknown" || diagnostics.MapOccupancy.Error != "map enumeration incomplete" ||
		len(diagnostics.MapOccupancy.Maps) != 1 || diagnostics.MapOccupancy.Maps[0].Entries != 3 {
		t.Fatalf("unexpected map occupancy: %+v", diagnostics.MapOccupancy)
	}
}

// TestDiagnosticsReportsNormalWithAHealthyAttachment covers the ordinary
// case: local TC configured and actually attached to an interface, nothing
// failing, no rollback anomaly.
func TestDiagnosticsReportsNormalWithAHealthyAttachment(t *testing.T) {
	inbound := &Inbound{localEnabled: true, localDataPlane: localDataPlaneTC}
	inbound.tcDataPlane = &testTCRuntime{
		attachments: []commonEBPF.AttachmentInfo{{
			InterfaceName:  "eth0",
			InterfaceIndex: 2,
			Role:           "local",
			Mechanism:      "tcx",
		}},
	}
	diagnostics := inbound.Diagnostics()
	if diagnostics.State != EBPFDiagnosticsStateNormal {
		t.Fatalf("state = %s, want %s", diagnostics.State, EBPFDiagnosticsStateNormal)
	}
	if len(diagnostics.Attachments) != 1 || diagnostics.Attachments[0].InterfaceName != "eth0" {
		t.Fatalf("attachments = %+v, want one entry for eth0", diagnostics.Attachments)
	}
	if diagnostics.Attachments[0].Mechanism != "tcx" || diagnostics.Attachments[0].Role != "local" {
		t.Fatalf("attachment = %+v, want mechanism=tcx role=local", diagnostics.Attachments[0])
	}
}

// TestDiagnosticsReportsRecoveringWhileAGeneralFailureIsOutstanding proves
// recordTCUpdateOutcome's wiring: a Recoverable outcome from the update loop
// shows up as RecoveryPending and the "recovering" state, without needing a
// real interface at all.
func TestDiagnosticsReportsRecoveringWhileAGeneralFailureIsOutstanding(t *testing.T) {
	inbound := &Inbound{}
	inbound.recordTCUpdateOutcome(tcUpdateOutcome{
		sharedRewrite: tcSharedRewriteSettled,
		general:       tcSharedRewriteRecoverable,
		bypassRuleSet: tcSharedRewriteSettled,
	})
	diagnostics := inbound.Diagnostics()
	if !diagnostics.RecoveryPending {
		t.Fatal("RecoveryPending = false, want true with a Recoverable general outcome")
	}
	if diagnostics.State != EBPFDiagnosticsStateRecovering {
		t.Fatalf("state = %s, want %s", diagnostics.State, EBPFDiagnosticsStateRecovering)
	}
}

// TestDiagnosticsRecordsRecoveryTimeOnTransitionToSettled proves
// LastRecoveryAt is set exactly when a previously-Recoverable component
// transitions to Settled, not on every Settled round (which would make it
// meaningless -- almost every round is Settled).
func TestDiagnosticsRecordsRecoveryTimeOnTransitionToSettled(t *testing.T) {
	inbound := &Inbound{}
	inbound.recordTCUpdateOutcome(tcUpdateOutcome{
		sharedRewrite: tcSharedRewriteSettled,
		general:       tcSharedRewriteSettled,
		bypassRuleSet: tcSharedRewriteSettled,
	})
	if diagnostics := inbound.Diagnostics(); diagnostics.LastRecoveryAt != nil {
		t.Fatalf("LastRecoveryAt = %v, want nil before any failure ever happened", diagnostics.LastRecoveryAt)
	}
	inbound.recordTCUpdateOutcome(tcUpdateOutcome{
		sharedRewrite: tcSharedRewriteSettled,
		general:       tcSharedRewriteRecoverable,
		bypassRuleSet: tcSharedRewriteSettled,
	})
	if diagnostics := inbound.Diagnostics(); diagnostics.LastRecoveryAt != nil {
		t.Fatalf("LastRecoveryAt = %v, want nil while still failing", diagnostics.LastRecoveryAt)
	}
	before := time.Now()
	inbound.recordTCUpdateOutcome(tcUpdateOutcome{
		sharedRewrite: tcSharedRewriteSettled,
		general:       tcSharedRewriteSettled,
		bypassRuleSet: tcSharedRewriteSettled,
	})
	diagnostics := inbound.Diagnostics()
	if diagnostics.LastRecoveryAt == nil {
		t.Fatal("LastRecoveryAt = nil, want set after a Recoverable -> Settled transition")
	}
	if diagnostics.LastRecoveryAt.Before(before) {
		t.Fatalf("LastRecoveryAt = %v, want at or after %v", diagnostics.LastRecoveryAt, before)
	}
}

// TestDiagnosticsReportsNeedsAttentionWhenUnrecoverable is an independent
// review's finding: an Unrecoverable component (the backend reported
// itself closed or requiring a rebuild the scheduler cannot perform on its
// own) was not checked anywhere in deriveDiagnosticsState at all --
// RecoveryPending only ever looked for Recoverable, so an Unrecoverable
// shared packet-rewrite backend with its attachment record still present
// (attachmentHasRole is satisfied, so waiting_for_interface never
// triggers either) fell all the way through to State=normal, exactly the
// state an operator would least expect for a backend that has given up.
func TestDiagnosticsReportsNeedsAttentionWhenUnrecoverable(t *testing.T) {
	inbound := &Inbound{sharedEnabled: true, sharedDataPlane: sharedDataPlanePacketRewrite, udpTimeout: time.Minute}
	shared := newSharedRewrite(inbound, option.EBPFSharedOptions{})
	shared.setDataPlane(&testSharedKernelRuntime{
		attachments: []commonEBPF.AttachmentInfo{{
			InterfaceName:  "eth0",
			InterfaceIndex: 2,
			Role:           "shared",
			Mechanism:      "tcx",
		}},
	})
	inbound.setSharedRewrite(shared)
	inbound.recordTCUpdateOutcome(tcUpdateOutcome{
		sharedRewrite: tcSharedRewriteUnrecoverable,
		general:       tcSharedRewriteSettled,
		bypassRuleSet: tcSharedRewriteSettled,
	})
	diagnostics := inbound.Diagnostics()
	if !diagnostics.RecoveryUnrecoverable {
		t.Fatal("RecoveryUnrecoverable = false, want true with an Unrecoverable shared-rewrite outcome")
	}
	if diagnostics.State != EBPFDiagnosticsStateNeedsAttention {
		t.Fatalf("state = %q, want %q", diagnostics.State, EBPFDiagnosticsStateNeedsAttention)
	}
}

func TestDiagnosticsIncludesBypassRuleSetRecovery(t *testing.T) {
	inbound := &Inbound{}
	inbound.recordTCUpdateOutcome(tcUpdateOutcome{
		sharedRewrite: tcSharedRewriteSettled,
		general:       tcSharedRewriteSettled,
		bypassRuleSet: tcSharedRewriteRecoverable,
	})
	if diagnostics := inbound.Diagnostics(); !diagnostics.RecoveryPending {
		t.Fatal("RecoveryPending = false with a recoverable bypass_rule_set update")
	}
	inbound.recordTCUpdateOutcome(tcUpdateOutcome{
		sharedRewrite: tcSharedRewriteSettled,
		general:       tcSharedRewriteSettled,
		bypassRuleSet: tcSharedRewriteUnrecoverable,
	})
	diagnostics := inbound.Diagnostics()
	if !diagnostics.RecoveryUnrecoverable || diagnostics.State != EBPFDiagnosticsStateNeedsAttention {
		t.Fatalf("unrecoverable bypass_rule_set diagnostics = %+v", diagnostics)
	}
}

// TestDiagnosticsUnrecoverableSurvivesAnUnknownRound ensures an unevaluated
// component cannot erase a previously reported unrecoverable state.
func TestDiagnosticsUnrecoverableSurvivesAnUnknownRound(t *testing.T) {
	inbound := &Inbound{}
	inbound.recordTCUpdateOutcome(tcUpdateOutcome{
		sharedRewrite: tcSharedRewriteUnrecoverable,
		general:       tcSharedRewriteSettled,
		bypassRuleSet: tcSharedRewriteSettled,
	})
	if diagnostics := inbound.Diagnostics(); diagnostics.State != EBPFDiagnosticsStateNeedsAttention {
		t.Fatalf("state after the Unrecoverable round = %q, want %q", diagnostics.State, EBPFDiagnosticsStateNeedsAttention)
	}
	// A later round that never re-evaluated sharedRewrite this time (its
	// zero value, Unknown) must not be read as "settled".
	inbound.recordTCUpdateOutcome(tcUpdateOutcome{
		general:       tcSharedRewriteRecoverable,
		bypassRuleSet: tcSharedRewriteSettled,
	})
	diagnostics := inbound.Diagnostics()
	if !diagnostics.RecoveryUnrecoverable {
		t.Fatal("RecoveryUnrecoverable = false after an Unknown round, want the prior Unrecoverable result preserved")
	}
	if diagnostics.State != EBPFDiagnosticsStateNeedsAttention {
		t.Fatalf("state after the Unknown round = %q, want %q (an Unknown round must not erase an unresolved fault)", diagnostics.State, EBPFDiagnosticsStateNeedsAttention)
	}
}

// TestDiagnosticsUDPSessionCountIncludesSharedPacketRewriteClients covers a
// packet-rewrite-only inbound with no local UDP client table.
func TestDiagnosticsUDPSessionCountIncludesSharedPacketRewriteClients(t *testing.T) {
	inbound := &Inbound{udpTimeout: time.Minute}
	shared := newSharedRewrite(inbound, option.EBPFSharedOptions{})
	inbound.setSharedRewrite(shared)
	shared.sharedUDPClientTable.loadOrCreate(udpSessionKey{
		Source: netip.MustParseAddrPort("192.0.2.1:12345"),
		Scope:  udpSessionScopeSharedRewrite,
	})

	diagnostics := inbound.Diagnostics()
	if diagnostics.UDPSessionCount != 1 {
		t.Fatalf("UDPSessionCount = %d, want 1 with one live shared packet-rewrite UDP client and no local clients", diagnostics.UDPSessionCount)
	}
}

// TestDiagnosticsReportsNeedsAttentionWhenBypassRuleSetIsInconsistent proves
// the one state that is not expected to self-heal on its own gets reported
// distinctly from an ordinary in-progress recovery.
func TestDiagnosticsReportsNeedsAttentionWhenBypassRuleSetIsInconsistent(t *testing.T) {
	inbound := &Inbound{}
	inbound.bypassRuleSetInconsistent = true
	diagnostics := inbound.Diagnostics()
	if diagnostics.LocalBypassRuleSet.Consistent {
		t.Fatal("LocalBypassRuleSet.Consistent = true, want false")
	}
	if diagnostics.State != EBPFDiagnosticsStateNeedsAttention {
		t.Fatalf("state = %s, want %s", diagnostics.State, EBPFDiagnosticsStateNeedsAttention)
	}
}

// TestDiagnosticsLastErrorPicksTheMostRecentAcrossCategories proves the
// cross-category "most recent wins" selection actually compares timestamps
// rather than, say, always preferring one fixed category.
func TestDiagnosticsLastErrorPicksTheMostRecentAcrossCategories(t *testing.T) {
	inbound := &Inbound{}
	inbound.interfaceWarnings.topology.record(time.Now().Add(-time.Minute), "older: topology issue")
	inbound.policyWarnings.record(time.Now(), "newer: policy issue")
	diagnostics := inbound.Diagnostics()
	if !strings.Contains(diagnostics.LastError, "newer: policy issue") {
		t.Fatalf("LastError = %q, want the more recent policy warning", diagnostics.LastError)
	}
}

func TestDiagnosticsLastErrorIncludesSharedRewriteWarnings(t *testing.T) {
	inbound := &Inbound{}
	inbound.policyWarnings.record(time.Now().Add(-time.Minute), "older: policy issue")
	shared := &sharedRewrite{}
	shared.udpWarnings.originalDestination.record(time.Now(), "newer: shared UDP issue")
	inbound.setSharedRewrite(shared)
	diagnostics := inbound.Diagnostics()
	if diagnostics.LastError != "newer: shared UDP issue" {
		t.Fatalf("LastError = %q, want the shared packet-rewrite warning", diagnostics.LastError)
	}
}

// TestDiagnosticsWriteJSONRoundTrips proves the JSON writer actually
// produces valid, complete JSON matching the struct's fields -- not just
// that it doesn't panic.
func TestDiagnosticsWriteJSONRoundTrips(t *testing.T) {
	inbound := &Inbound{localEnabled: true, localDataPlane: localDataPlaneTC}
	diagnostics := inbound.Diagnostics()
	var buffer bytes.Buffer
	if err := diagnostics.WriteJSON(&buffer); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	var decoded EBPFDiagnostics
	if err := json.Unmarshal(buffer.Bytes(), &decoded); err != nil {
		t.Fatalf("decode JSON: %v (input: %s)", err, buffer.String())
	}
	if decoded.State != diagnostics.State {
		t.Fatalf("decoded state = %s, want %s", decoded.State, diagnostics.State)
	}
}

// TestDiagnosticsWriteTextIncludesTheKeyFields covers the text-only fields.
func TestDiagnosticsWriteTextIncludesTheKeyFields(t *testing.T) {
	inbound := &Inbound{localEnabled: true, localDataPlane: localDataPlaneTC}
	diagnostics := inbound.Diagnostics()
	var buffer bytes.Buffer
	if err := diagnostics.WriteText(&buffer); err != nil {
		t.Fatalf("WriteText: %v", err)
	}
	text := buffer.String()
	for _, want := range []string{
		"Tag:", "State:", "Attachments:", "Recovery pending:", "UDP sessions:", "UDP NAT:", "UDP reply sockets:",
		"tc_socket_lookup_failures=", "tc_sk_assign_failures=", "tc_assignment_update_failures=",
		"tc_local_fragment_passes=", "tc_shared_fragment_passes=",
		"shared_ingress_fragment_passes=", "shared_egress_fragment_passes=",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("text output missing %q; got:\n%s", want, text)
		}
	}
	for _, unwanted := range []string{"shared_ingress_passes=", "shared_egress_passes="} {
		if strings.Contains(text, unwanted) {
			t.Fatalf("text output still reports removed counter %q; got:\n%s", unwanted, text)
		}
	}
}

// TestLogStartupSummaryNamesEachRequiredFact checks enabled paths, mounts,
// waiting interfaces, and FakeIP coverage in the single Debug line.
func TestLogStartupSummaryNamesEachRequiredFact(t *testing.T) {
	logger := &captureLogger{}
	inbound := &Inbound{
		localEnabled:    true,
		localDataPlane:  localDataPlaneTC,
		fakeIPICMPReply: true,
		logger:          logger,
	}
	inbound.logStartupSummary()

	if len(logger.debugMessages) != 1 || len(logger.infoMessages) != 0 {
		t.Fatalf("log calls: Debug=%d Info=%d, want Debug=1 Info=0", len(logger.debugMessages), len(logger.infoMessages))
	}
	message := logger.debugMessages[0]
	for _, want := range []string{"local=tc", "waiting_for_interface=[local]", "fakeip_icmp=[enabled, not yet covering any attachment]"} {
		if !strings.Contains(message, want) {
			t.Fatalf("summary %q missing %q", message, want)
		}
	}
}

// TestLogStartupSummaryReportsAnActualAttachmentAndItsFakeIPICMPCoverage
// covers the other half: a real attachment gets named by interface and
// mechanism, and when fakeip_icmp actually covers it, that attachment name
// appears rather than the "not yet covering" fallback.
func TestLogStartupSummaryReportsAnActualAttachmentAndItsFakeIPICMPCoverage(t *testing.T) {
	logger := &captureLogger{}
	inbound := &Inbound{
		localEnabled:    true,
		localDataPlane:  localDataPlaneTC,
		fakeIPICMPReply: true,
		logger:          logger,
	}
	inbound.tcDataPlane = &testTCRuntime{
		attachments: []commonEBPF.AttachmentInfo{{
			InterfaceName: "eth0",
			Role:          "local",
			Mechanism:     "tcx",
			ICMPEchoReply: true,
		}},
	}
	inbound.logStartupSummary()

	if len(logger.debugMessages) != 1 || len(logger.infoMessages) != 0 {
		t.Fatalf("log calls: Debug=%d Info=%d, want Debug=1 Info=0", len(logger.debugMessages), len(logger.infoMessages))
	}
	message := logger.debugMessages[0]
	for _, want := range []string{"mounts=[eth0(local,tcx)]", "waiting_for_interface=[none]", "fakeip_icmp=[eth0(local)]"} {
		if !strings.Contains(message, want) {
			t.Fatalf("summary %q missing %q", message, want)
		}
	}
}

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
