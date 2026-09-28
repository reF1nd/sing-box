//go:build with_ebpf && (linux || android)

package ebpf

import (
	"testing"
)

type testFakeIPICMPCounterSource struct {
	enabled         bool
	replies         uint64
	passThrough     uint64
	rewriteFailures uint64
}

func (s testFakeIPICMPCounterSource) ICMPEchoReplyEnabled() bool { return s.enabled }
func (s testFakeIPICMPCounterSource) ICMPEchoReplyCount() (uint64, error) {
	return s.replies, nil
}
func (s testFakeIPICMPCounterSource) ICMPEchoPassThroughCount() (uint64, error) {
	return s.passThrough, nil
}
func (s testFakeIPICMPCounterSource) ICMPEchoRewriteFailureCount() (uint64, error) {
	return s.rewriteFailures, nil
}

func TestAddFakeIPICMPCountersSumsEnabledBackends(t *testing.T) {
	counters := EBPFCounters{}
	addFakeIPICMPCounters(
		&counters,
		testFakeIPICMPCounterSource{enabled: true, replies: 2, passThrough: 3, rewriteFailures: 5},
		testFakeIPICMPCounterSource{enabled: false, replies: 100, passThrough: 100, rewriteFailures: 100},
		testFakeIPICMPCounterSource{enabled: true, replies: 7, passThrough: 11, rewriteFailures: 13},
	)
	if counters.FakeIPICMPReplies != 9 || counters.FakeIPICMPPassThrough != 14 || counters.FakeIPICMPRewriteFailureDrops != 18 {
		t.Fatalf("fakeip_icmp counters = %+v, want replies=9 pass-through=14 rewrite-failures=18", counters)
	}
}

// TestDiagnosticsFakeIPICMPCountersZeroWhenDisabled confirms a backend with
// fakeip_icmp off reports zero counters rather than an error surfacing as a
// nonzero/garbage value.
func TestDiagnosticsFakeIPICMPCountersZeroWhenDisabled(t *testing.T) {
	backend := newLoopbackTestTCBackend(t)

	inbound := &Inbound{localEnabled: true, localDataPlane: localDataPlaneTC}
	inbound.tcDataPlane = newUnstartedTCRuntime(backend)

	counters := inbound.Diagnostics().Counters
	if counters.FakeIPICMPReplies != 0 || counters.FakeIPICMPPassThrough != 0 || counters.FakeIPICMPRewriteFailureDrops != 0 {
		t.Fatalf("fakeip_icmp counters = %+v, want all zero when fakeip_icmp was never enabled", counters)
	}
}
