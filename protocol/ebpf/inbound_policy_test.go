//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net/netip"
	"reflect"
	"testing"

	commonEBPF "github.com/CHIZI-0618/sing-ebpf"
	"github.com/sagernet/sing-box/log"
)

// TestRevertBypassCIDRBackendsRevertsMostRecentFirst proves the unwind order:
// the backend that was applied last (and so is most likely to be the one
// whose own failure triggered the unwind) is reverted first, matching how a
// stack of partially-applied changes is normally unwound.
func TestRevertBypassCIDRBackendsRevertsMostRecentFirst(t *testing.T) {
	var order []string
	applied := []bypassCIDRAppliedBackend{
		{name: "TC", revert: func() error { order = append(order, "TC"); return nil }},
		{name: "cgroup", revert: func() error { order = append(order, "cgroup"); return nil }},
		{name: "shared", revert: func() error { order = append(order, "shared"); return nil }},
	}
	failed := revertBypassCIDRBackends(applied, func(string, error) { t.Fatal("no revert should fail in this case") })
	if len(failed) != 0 {
		t.Fatalf("failed = %v, want none", failed)
	}
	want := []string{"shared", "cgroup", "TC"}
	if len(order) != len(want) {
		t.Fatalf("revert order = %v, want %v", order, want)
	}
	for index, name := range want {
		if order[index] != name {
			t.Fatalf("revert order = %v, want %v", order, want)
		}
	}
}

// TestRevertBypassCIDRBackendsReportsEveryFailedPath proves the unwind does
// not stop at the first backend that refuses to revert: a later backend
// (earlier in application order) that also cannot revert is exactly as
// important to report as the first, since both are now on the new policy
// with no compensating change applied.
func TestRevertBypassCIDRBackendsReportsEveryFailedPath(t *testing.T) {
	tcErr := errString("TC revert failed")
	sharedErr := errString("shared revert failed")
	applied := []bypassCIDRAppliedBackend{
		{name: "TC", revert: func() error { return tcErr }},
		{name: "cgroup", revert: func() error { return nil }},
		{name: "shared", revert: func() error { return sharedErr }},
	}
	var warned []string
	failed := revertBypassCIDRBackends(applied, func(name string, err error) { warned = append(warned, name) })
	if len(failed) != 2 || failed[0] != "shared" || failed[1] != "TC" {
		t.Fatalf("failed = %v, want [shared TC] (revert order, both reported despite TC being tried after cgroup succeeded)", failed)
	}
	if len(warned) != 2 {
		t.Fatalf("warn was called %d times, want once per failed backend", len(warned))
	}
}

type errString string

func (e errString) Error() string { return string(e) }

// newLoopbackTestTCBackend prepares a real TC eBPF backend with no interface
// attachment at all -- exactly what applyBypassCIDRPolicyLocked needs, since
// it only ever calls the backend's own policy-update methods, never anything
// attachment-related.
func newLoopbackTestTCBackend(t *testing.T) *commonEBPF.TCBackend {
	t.Helper()
	policy, err := commonEBPF.CompilePolicy(commonEBPF.PolicyConfig{EnableTCP: true})
	if err != nil {
		t.Fatalf("compile policy: %v", err)
	}
	backend, err := commonEBPF.PrepareTC(commonEBPF.TCConfig{
		ListenerPort: 23457,
		EnableLocal:  true,
		EnableIPv4:   true,
		EnableTCP:    true,
		Policy:       policy,
	})
	if err != nil {
		t.Skipf("cannot prepare a real TC eBPF backend in this environment: %v", err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	return backend
}

func bypassPolicyFor(t *testing.T, prefixes ...netip.Prefix) commonEBPF.BypassCIDRPolicy {
	t.Helper()
	policy, err := commonEBPF.CompileBypassCIDRPolicy(prefixes)
	if err != nil {
		t.Fatalf("compile bypass CIDR policy: %v", err)
	}
	return policy
}

// TestApplyBypassCIDRPolicyRevertsAnEarlierBackendWhenALaterOneFails verifies
// that a later backend failure restores an already-updated TC backend.
//
// TC's own state is not directly observable from outside sing-ebpf, so
// this checks it indirectly: calling UpdateCompiledBypassCIDR with the
// previous policy again afterward must report changed=false -- the backend
// is already there -- which would be false (changed=true, a real diff) had
// the revert not actually happened.
//
// It also covers version bookkeeping on this successful-revert
// path: bypassRuleSetPolicyVersion is committed only alongside
// bypassRuleSetPolicy, so a fully-reverted failed attempt leaves both at
// their pre-attempt values -- it does not advance just because an attempt
// was made. TC's own per-backend version -- having moved to the new value
// while its forward apply was the only thing that had happened -- is rolled
// back to the version it held before this call, and marked known=true,
// once its compensating revert also succeeds, so a diagnostics reader sees
// TC as caught back up to what bypassRuleSetPolicy itself was rolled back
// to, not left claiming a version it never actually kept.
func TestApplyBypassCIDRPolicyRevertsAnEarlierBackendWhenALaterOneFails(t *testing.T) {
	tc := newLoopbackTestTCBackend(t)
	previous := bypassPolicyFor(t, netip.MustParsePrefix("10.0.0.0/8"))
	next := bypassPolicyFor(t, netip.MustParsePrefix("192.168.0.0/16"))

	inbound := &Inbound{}
	inbound.tcDataPlane = newUnstartedTCRuntime(tc)
	inbound.setCgroupBackend(&commonEBPF.CgroupBackend{}) // zero value: never usable
	inbound.bypassRuleSetPolicy = previous
	inbound.bypassRuleSetPolicyVersion = 5
	inbound.bypassRuleSetExpectedPolicy = previous
	inbound.bypassRuleSetExpectedVersion = 5
	inbound.bypassRuleSetTC = bypassRuleSetBackendVersion{version: 5, known: true}

	err := inbound.applyBypassCIDRPolicyLocked(next)
	if err == nil {
		t.Fatal("apply succeeded despite the cgroup backend being permanently unusable")
	}
	if inbound.bypassRuleSetInconsistent {
		t.Fatal("marked inconsistent even though TC's own revert had no reason to fail")
	}
	if !reflect.DeepEqual(inbound.bypassRuleSetPolicy, previous) {
		t.Fatalf("bypassRuleSetPolicy = %+v, want it left at the previous policy on failure", inbound.bypassRuleSetPolicy)
	}
	changed, revertCheckErr := tc.UpdateCompiledBypassCIDR(previous)
	if revertCheckErr != nil {
		t.Fatalf("re-apply the previous policy to check TC's state: %v", revertCheckErr)
	}
	if changed {
		t.Fatal("TC backend was not actually reverted to the previous policy: re-applying it was not a no-op")
	}
	if inbound.bypassRuleSetPolicyVersion != 5 {
		t.Fatalf(
			"bypassRuleSetPolicyVersion = %d, want 5 (unchanged: the overall attempt failed and was fully reverted, "+
				"so the policy version must not have advanced even though an attempt was made)",
			inbound.bypassRuleSetPolicyVersion,
		)
	}
	if inbound.bypassRuleSetTC != (bypassRuleSetBackendVersion{version: 5, known: true}) {
		t.Fatalf("bypassRuleSetTC = %+v, want {version:5 known:true} (rolled back once TC's own revert succeeded)", inbound.bypassRuleSetTC)
	}
}

// TestApplyBypassCIDRPolicyLeavesBackendVersionOnFailedRevert is the
// companion to the test above for the case EBPFDiagnostics'
// BypassRuleSetConsistent=false is meant to flag: a backend's own
// compensating revert fails too, so its true state relative to
// bypassRuleSetPolicy is unknown. Its recorded version is left at the value
// it reached during this attempt's forward apply (the last point it was
// actually confirmed at), but known flips to false -- a diagnostics reader
// must treat that version as "last seen here, not confirmed now", never as
// "currently running this version".
//
// TC's UpdateCompiledBypassCIDR rejects any policy over
// commonEBPF's compiled-in bypass CIDR map capacity (65536 entries)
// before touching the backend's state at all, independent of whether the
// backend is otherwise healthy. That check is used here, rather than a
// fake/mock backend, to make the revert call itself fail with a real,
// reproducible error without adding a test-only seam to the production
// type: "previous" is deliberately compiled from more prefixes than the
// cap allows (each one isolated so compileBypassCIDRPolicy's set builder
// cannot merge them into fewer, in-cap prefixes), so the forward apply of
// a small, valid "next" policy succeeds first, and only the later revert
// back to the oversized "previous" fails.
func TestApplyBypassCIDRPolicyLeavesBackendVersionOnFailedRevert(t *testing.T) {
	tc := newLoopbackTestTCBackend(t)
	previous := oversizedBypassPolicy(t)
	next := bypassPolicyFor(t, netip.MustParsePrefix("192.168.0.0/16"))

	inbound := &Inbound{}
	inbound.logger = log.NewNOPFactory().Logger()
	inbound.tcDataPlane = newUnstartedTCRuntime(tc)
	inbound.setCgroupBackend(&commonEBPF.CgroupBackend{}) // zero value: never usable
	inbound.bypassRuleSetPolicy = previous
	inbound.bypassRuleSetPolicyVersion = 5
	inbound.bypassRuleSetExpectedPolicy = previous
	inbound.bypassRuleSetExpectedVersion = 5
	inbound.bypassRuleSetTC = bypassRuleSetBackendVersion{version: 5, known: true}

	err := inbound.applyBypassCIDRPolicyLocked(next)
	if err == nil {
		t.Fatal("apply succeeded despite the cgroup backend being permanently unusable")
	}
	if !inbound.bypassRuleSetInconsistent {
		t.Fatal("want bypassRuleSetInconsistent=true: TC's own revert to the oversized previous policy must have failed")
	}
	if inbound.bypassRuleSetPolicyVersion != 5 {
		t.Fatalf(
			"bypassRuleSetPolicyVersion = %d, want 5 (unchanged: bypassRuleSetPolicy itself was never updated on this "+
				"failed attempt, so the version naming it must not move either)",
			inbound.bypassRuleSetPolicyVersion,
		)
	}
	if inbound.bypassRuleSetTC.known {
		t.Fatal("bypassRuleSetTC.known = true, want false: TC's own revert failed, so its true state is unconfirmed")
	}
	if inbound.bypassRuleSetTC.version != 6 {
		t.Fatalf(
			"bypassRuleSetTC.version = %d, want 6 (the last point TC was actually confirmed at -- its own successful "+
				"forward apply during this same attempt -- retained alongside known=false, not silently reverted to "+
				"a number that would claim a confirmed state)",
			inbound.bypassRuleSetTC.version,
		)
	}
}

// TestApplyBypassCIDRPolicyVersionUnchangedForIdenticalContent proves
// bypassRuleSetPolicyVersion is a content-based policy version, not an
// attempt counter: re-applying the exact same compiled policy -- the shape
// a scheduler retry of the same failed content takes, or an unrelated
// rule-set callback that happens to recompile to identical prefixes -- must
// not mint a new version.
func TestApplyBypassCIDRPolicyVersionUnchangedForIdenticalContent(t *testing.T) {
	tc := newLoopbackTestTCBackend(t)
	policy := bypassPolicyFor(t, netip.MustParsePrefix("192.168.0.0/16"))

	inbound := &Inbound{}
	inbound.tcDataPlane = newUnstartedTCRuntime(tc)

	if err := inbound.applyBypassCIDRPolicyLocked(policy); err != nil {
		t.Fatalf("first apply: %v", err)
	}
	firstVersion := inbound.bypassRuleSetPolicyVersion
	if firstVersion == 0 {
		t.Fatal("bypassRuleSetPolicyVersion did not advance on the very first apply")
	}

	if err := inbound.applyBypassCIDRPolicyLocked(policy); err != nil {
		t.Fatalf("second, identical apply: %v", err)
	}
	if inbound.bypassRuleSetPolicyVersion != firstVersion {
		t.Fatalf(
			"bypassRuleSetPolicyVersion = %d after re-applying identical content, want unchanged from %d",
			inbound.bypassRuleSetPolicyVersion, firstVersion,
		)
	}

	changed := bypassPolicyFor(t, netip.MustParsePrefix("10.0.0.0/8"))
	if err := inbound.applyBypassCIDRPolicyLocked(changed); err != nil {
		t.Fatalf("third apply with different content: %v", err)
	}
	if inbound.bypassRuleSetPolicyVersion != firstVersion+1 {
		t.Fatalf(
			"bypassRuleSetPolicyVersion = %d after applying genuinely different content, want %d",
			inbound.bypassRuleSetPolicyVersion, firstVersion+1,
		)
	}
}

// TestBypassRuleSetRetryCountOnlyCountsSchedulerRetries proves
// bypassRuleSetRetryCount is distinct from bypassRuleSetPolicyVersion: it
// counts specifically how many times retryBypassRuleSetIfNeededLocked has
// retried a previously-failed apply, not every call that happens to reach
// applyBypassCIDRPolicyLocked. An ordinary refresh (the shape a startup
// call or a rule-set update callback takes) must leave it untouched, and
// retryBypassRuleSetIfNeededLocked itself must not count a round where
// nothing actually needed retrying.
func TestBypassRuleSetRetryCountOnlyCountsSchedulerRetries(t *testing.T) {
	tc := newLoopbackTestTCBackend(t)

	inbound := &Inbound{}
	inbound.logger = log.NewNOPFactory().Logger()
	inbound.tcDataPlane = newUnstartedTCRuntime(tc)
	inbound.bypassRuleSetStarted = true

	if err := inbound.refreshBypassRuleSetsLocked(false); err != nil {
		t.Fatalf("ordinary refresh: %v", err)
	}
	if inbound.bypassRuleSetRetryCount != 0 {
		t.Fatalf("bypassRuleSetRetryCount = %d, want 0 after an ordinary refresh that was not a retry", inbound.bypassRuleSetRetryCount)
	}

	if outcome := inbound.retryBypassRuleSetIfNeededLocked(); outcome != tcSharedRewriteSettled {
		t.Fatalf("outcome = %v, want settled when bypassRuleSetNeedsRetry is false", outcome)
	}
	if inbound.bypassRuleSetRetryCount != 0 {
		t.Fatalf("bypassRuleSetRetryCount = %d, want 0: nothing needed a retry, so none should be counted", inbound.bypassRuleSetRetryCount)
	}

	inbound.bypassRuleSetNeedsRetry = true
	if outcome := inbound.retryBypassRuleSetIfNeededLocked(); outcome != tcSharedRewriteSettled {
		t.Fatalf("outcome = %v, want settled once the retried refresh succeeds", outcome)
	}
	if inbound.bypassRuleSetRetryCount != 1 {
		t.Fatalf("bypassRuleSetRetryCount = %d, want 1 after exactly one scheduler-driven retry", inbound.bypassRuleSetRetryCount)
	}
}

// oversizedBypassPolicy compiles a BypassCIDRPolicy with one more IPv4
// prefix than commonEBPF's bypass CIDR map capacity allows, guaranteed not
// to collapse into fewer, in-cap prefixes: each address is spaced four
// apart, so no two are adjacent and compileBypassCIDRPolicy's IPSetBuilder
// cannot merge any of them into a larger CIDR block.
func oversizedBypassPolicy(t *testing.T) commonEBPF.BypassCIDRPolicy {
	t.Helper()
	const entries = 65537
	prefixes := make([]netip.Prefix, 0, entries)
	for i := 0; i < entries; i++ {
		offset := uint32(i) * 4
		addr := netip.AddrFrom4([4]byte{10, byte(offset >> 16), byte(offset >> 8), byte(offset)})
		prefixes = append(prefixes, netip.PrefixFrom(addr, 32))
	}
	return bypassPolicyFor(t, prefixes...)
}

// TestApplyBypassCIDRPolicySucceedsAcrossRealBackends is the companion
// clean-path proof: with every backend usable, the policy lands on all of
// them and bypassRuleSetPolicy tracks the new value, and the version
// bookkeeping reflects a single successful, content-changing apply: the
// policy version advances by one, and TC's own state is set to that same
// new version with known=true.
func TestApplyBypassCIDRPolicySucceedsAcrossRealBackends(t *testing.T) {
	tc := newLoopbackTestTCBackend(t)
	next := bypassPolicyFor(t, netip.MustParsePrefix("192.168.0.0/16"))

	inbound := &Inbound{}
	inbound.tcDataPlane = newUnstartedTCRuntime(tc)
	inbound.bypassRuleSetPolicyVersion = 5
	inbound.bypassRuleSetExpectedVersion = 5
	inbound.bypassRuleSetTC = bypassRuleSetBackendVersion{version: 5, known: true}

	if err := inbound.applyBypassCIDRPolicyLocked(next); err != nil {
		t.Fatalf("apply with only a healthy TC backend: %v", err)
	}
	if !reflect.DeepEqual(inbound.bypassRuleSetPolicy, next) {
		t.Fatalf("bypassRuleSetPolicy = %+v, want the newly-applied policy", inbound.bypassRuleSetPolicy)
	}
	if inbound.bypassRuleSetInconsistent {
		t.Fatal("marked inconsistent after a fully successful apply")
	}
	if inbound.bypassRuleSetPolicyVersion != 6 {
		t.Fatalf("bypassRuleSetPolicyVersion = %d, want 6 (content genuinely changed from the starting version)", inbound.bypassRuleSetPolicyVersion)
	}
	if inbound.bypassRuleSetTC != (bypassRuleSetBackendVersion{version: 6, known: true}) {
		t.Fatalf("bypassRuleSetTC = %+v, want {version:6 known:true} (TC caught up to the new version on a successful apply)", inbound.bypassRuleSetTC)
	}
}

// TestBypassRuleSetExpectedVersionTracksTheLatestAttemptEvenOnFailure proves
// the distinction EBPFDiagnostics' BypassRuleSetExpectedPolicyVersion exists
// for: bypassRuleSetPolicyVersion only ever names the last successfully
// applied content, but a diagnostics reader watching while a retry is
// outstanding needs to see what this inbound is currently trying to
// converge to, which a failed attempt must expose immediately -- not only
// once some later retry happens to succeed.
//
// It also proves the retry path actually chases the latest content, not a
// stale snapshot of whichever attempt first failed: a second, different
// failed attempt must move the expected version again immediately
// (superseding the first), and the retry that finally succeeds must land on
// that latest content, catching bypassRuleSetPolicyVersion up to
// bypassRuleSetExpectedVersion exactly -- never on the first, now-superseded
// attempt.
func TestBypassRuleSetExpectedVersionTracksTheLatestAttemptEvenOnFailure(t *testing.T) {
	tc := newLoopbackTestTCBackend(t)
	inbound := &Inbound{}
	inbound.logger = log.NewNOPFactory().Logger()
	inbound.tcDataPlane = newUnstartedTCRuntime(tc)
	inbound.setCgroupBackend(&commonEBPF.CgroupBackend{}) // zero value: never usable

	first := bypassPolicyFor(t, netip.MustParsePrefix("10.0.0.0/8"))
	if err := inbound.applyBypassCIDRPolicyLocked(first); err == nil {
		t.Fatal("apply succeeded despite the cgroup backend being permanently unusable")
	}
	if inbound.bypassRuleSetExpectedVersion != 1 {
		t.Fatalf(
			"bypassRuleSetExpectedVersion = %d, want 1 immediately after the first (failed) attempt -- "+
				"a diagnostics reader during the pending-retry window must see the target, not a stale value",
			inbound.bypassRuleSetExpectedVersion,
		)
	}
	if inbound.bypassRuleSetPolicyVersion != 0 {
		t.Fatalf("bypassRuleSetPolicyVersion = %d, want 0: nothing has actually succeeded yet", inbound.bypassRuleSetPolicyVersion)
	}

	// A second, different failed attempt -- e.g. a further rule-set change
	// arriving before the first attempt's own retry ever fires -- must move
	// the expected version again right away, proving a retry firing after
	// this point would chase this newer content, not the first attempt's.
	second := bypassPolicyFor(t, netip.MustParsePrefix("172.16.0.0/12"))
	if err := inbound.applyBypassCIDRPolicyLocked(second); err == nil {
		t.Fatal("apply succeeded despite the cgroup backend being permanently unusable")
	}
	if inbound.bypassRuleSetExpectedVersion != 2 {
		t.Fatalf(
			"bypassRuleSetExpectedVersion = %d, want 2: a second, different failed attempt must supersede the first immediately",
			inbound.bypassRuleSetExpectedVersion,
		)
	}
	if inbound.bypassRuleSetPolicyVersion != 0 {
		t.Fatalf("bypassRuleSetPolicyVersion = %d, want still 0: still nothing has actually succeeded", inbound.bypassRuleSetPolicyVersion)
	}

	// The retry that finally succeeds -- simulated here by removing the
	// failure source and re-attempting the latest (second) content, the
	// same content a real retryBypassRuleSetIfNeededLocked call would
	// recompute from the live rule sets at this point -- must land on that
	// latest content, not the first, now-superseded one, and must catch
	// bypassRuleSetPolicyVersion up to bypassRuleSetExpectedVersion exactly.
	inbound.setCgroupBackend(nil)
	if err := inbound.applyBypassCIDRPolicyLocked(second); err != nil {
		t.Fatalf("retry of the latest expected content: %v", err)
	}
	if inbound.bypassRuleSetPolicyVersion != inbound.bypassRuleSetExpectedVersion {
		t.Fatalf(
			"bypassRuleSetPolicyVersion = %d, bypassRuleSetExpectedVersion = %d, want them equal once the retry succeeds",
			inbound.bypassRuleSetPolicyVersion, inbound.bypassRuleSetExpectedVersion,
		)
	}
	if inbound.bypassRuleSetPolicyVersion != 2 {
		t.Fatalf("bypassRuleSetPolicyVersion = %d, want 2 (the second attempt's version, not the first's)", inbound.bypassRuleSetPolicyVersion)
	}
	if !reflect.DeepEqual(inbound.bypassRuleSetPolicy, second) {
		t.Fatalf("bypassRuleSetPolicy = %+v, want the second (latest expected) policy, not the first", inbound.bypassRuleSetPolicy)
	}
}

// TestUpdateBypassRuleSetWakesTheSchedulerOnFailure is an independent
// review's finding: updateBypassRuleSet's failure path set
// bypassRuleSetNeedsRetry but never actually woke the scheduler, despite
// its own comment claiming retryBypassRuleSetIfNeededLocked would "pick
// this back up" the same way other TC failures get retried. The scheduler
// only runs a round on a network event or its own ten-minute health-check
// tick (tcDriftCheckInterval) -- setting the flag alone does not cause
// either, so the very first retry attempt for a rule-set update failure
// would otherwise sit unnoticed for up to ten minutes, not the seconds
// -scale exponential backoff every other TC failure in this package gets.
func TestUpdateBypassRuleSetWakesTheSchedulerOnFailure(t *testing.T) {
	inbound := &Inbound{bypassRuleSetStarted: true}
	inbound.logger = log.NewNOPFactory().Logger()
	inbound.tcDataPlane = newUnstartedTCRuntime(&commonEBPF.TCBackend{}) // zero value: never usable
	inbound.interfaceMonitor.network = &testNetworkUpdateMonitor{}
	inbound.interfaceMonitor.updates = make(chan struct{}, 1)

	inbound.updateBypassRuleSet(nil)
	if !inbound.bypassRuleSetNeedsRetry {
		t.Fatal("fixture failed to create a pending bypass_rule_set retry -- the backend must be unusable for this test to mean anything")
	}
	select {
	case <-inbound.interfaceMonitor.updates:
	default:
		t.Fatal("failed rule-set callback left the scheduler asleep; the first retry would wait for a network event or the ten-minute health tick")
	}
}
