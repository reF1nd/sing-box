//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net/netip"
	"strings"
	"testing"
)

func TestNormalizeFakeIPICMP(t *testing.T) {
	for _, testCase := range []struct {
		mode    string
		enabled bool
		wantErr bool
	}{
		{"", false, false},
		{"off", false, false},
		{"reply", true, false},
		{"REPLY", false, true},
		{"on", false, true},
	} {
		enabled, err := normalizeFakeIPICMP(testCase.mode)
		if (err != nil) != testCase.wantErr {
			t.Fatalf("normalizeFakeIPICMP(%q) error = %v, wantErr %v", testCase.mode, err, testCase.wantErr)
		}
		if err == nil && enabled != testCase.enabled {
			t.Fatalf("normalizeFakeIPICMP(%q) = %v, want %v", testCase.mode, enabled, testCase.enabled)
		}
	}
}

// TestValidateFakeIPICMP covers every branch of the eBPF-only half of the
// fakeip_icmp=reply requirement: it needs a FakeIP prefix to answer for, and
// it needs to land on a data plane that actually has an attachment for it to
// ride — local.data_plane=tc or either shared.data_plane. Only
// local.data_plane=cgroup has no attachment at all to answer from (its
// connect()/sendmsg() hooks never see a packet), and is refused by name so a
// caller fixing the configuration sees why.
func TestValidateFakeIPICMP(t *testing.T) {
	fakeIPv4 := netip.MustParsePrefix("198.18.0.0/15")
	noPrefix := netip.Prefix{}

	for _, testCase := range []struct {
		name            string
		enabled         bool
		fakeIPIPv4      netip.Prefix
		localEnabled    bool
		localDataPlane  string
		sharedEnabled   bool
		sharedDataPlane string
		wantErr         bool
		wantErrContains string
	}{
		{name: "disabled is always fine", enabled: false},
		{
			name:    "disabled ignores a missing FakeIP prefix",
			enabled: false, fakeIPIPv4: noPrefix,
		},
		{
			name: "reply without any FakeIP prefix", enabled: true, fakeIPIPv4: noPrefix,
			localEnabled: true, localDataPlane: localDataPlaneTC,
			wantErr: true, wantErrContains: "requires a FakeIP range",
		},
		{
			name: "reply on local TC", enabled: true, fakeIPIPv4: fakeIPv4,
			localEnabled: true, localDataPlane: localDataPlaneTC,
			wantErr: false,
		},
		{
			name: "reply on local TC plus shared packet_rewrite covers both", enabled: true, fakeIPIPv4: fakeIPv4,
			localEnabled: true, localDataPlane: localDataPlaneTC,
			sharedEnabled: true, sharedDataPlane: sharedDataPlanePacketRewrite,
			wantErr: false,
		},
		{
			name: "reply on shared socket_assign", enabled: true, fakeIPIPv4: fakeIPv4,
			sharedEnabled: true, sharedDataPlane: sharedDataPlaneSocketAssign,
			wantErr: false,
		},
		{
			name: "reply on shared packet_rewrite alone", enabled: true, fakeIPIPv4: fakeIPv4,
			sharedEnabled: true, sharedDataPlane: sharedDataPlanePacketRewrite,
			wantErr: false,
		},
		{
			name: "reply on local cgroup alone is refused by name", enabled: true, fakeIPIPv4: fakeIPv4,
			localEnabled: true, localDataPlane: localDataPlaneCgroup,
			wantErr: true, wantErrContains: "local.data_plane=cgroup",
		},
		{
			name: "reply on cgroup plus shared socket_assign applies only to the shared path", enabled: true, fakeIPIPv4: fakeIPv4,
			localEnabled: true, localDataPlane: localDataPlaneCgroup,
			sharedEnabled: true, sharedDataPlane: sharedDataPlaneSocketAssign,
			wantErr: false,
		},
		{
			name: "reply on cgroup plus shared packet_rewrite applies only to the shared path", enabled: true, fakeIPIPv4: fakeIPv4,
			localEnabled: true, localDataPlane: localDataPlaneCgroup,
			sharedEnabled: true, sharedDataPlane: sharedDataPlanePacketRewrite,
			wantErr: false,
		},
		{
			name: "reply with nothing enabled at all", enabled: true, fakeIPIPv4: fakeIPv4,
			wantErr: true, wantErrContains: "requires local.data_plane=tc or shared interception",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			err := validateFakeIPICMP(
				testCase.enabled, testCase.fakeIPIPv4, netip.Prefix{},
				testCase.localEnabled, testCase.localDataPlane,
				testCase.sharedEnabled, testCase.sharedDataPlane,
			)
			if (err != nil) != testCase.wantErr {
				t.Fatalf("validateFakeIPICMP() error = %v, wantErr %v", err, testCase.wantErr)
			}
			if err != nil && testCase.wantErrContains != "" && !strings.Contains(err.Error(), testCase.wantErrContains) {
				t.Fatalf("validateFakeIPICMP() error = %q, want it to mention %q", err.Error(), testCase.wantErrContains)
			}
		})
	}
}
