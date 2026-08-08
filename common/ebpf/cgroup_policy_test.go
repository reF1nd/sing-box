//go:build with_ebpf && (linux || android)

package ebpf

import (
	"encoding/binary"
	"net/netip"
	"slices"
	"testing"
	"unsafe"
)

func TestCompileUIDRanges(t *testing.T) {
	if size := unsafe.Sizeof(uidLPMKey{}); size != 8 {
		t.Fatalf("unexpected UID LPM key size: %d", size)
	}
	entries := compileUIDRanges([]UIDRange{
		{Start: 0, End: 0},
		{Start: 1000, End: 99999},
	})
	for _, uid := range []uint32{0, 1000, 50000, 99999} {
		if !uidMatchesPrefixes(uid, entries) {
			t.Fatalf("UID %d is not covered", uid)
		}
	}
	for _, uid := range []uint32{1, 999, 100000} {
		if uidMatchesPrefixes(uid, entries) {
			t.Fatalf("UID %d is unexpectedly covered", uid)
		}
	}
}

func TestCompileFullUIDRange(t *testing.T) {
	entries := compileUIDRanges([]UIDRange{{Start: 0, End: ^uint32(0)}})
	if len(entries) != 1 || entries[0].PrefixLength != 0 {
		t.Fatalf("unexpected full UID range: %+v", entries)
	}
}

func TestCompileUIDPolicyPrecedence(t *testing.T) {
	entries, defaultBypass, err := compileUIDPolicy(CgroupPolicy{
		IncludeUIDConfigured: true,
		IncludeUID:           []UIDRange{{Start: 1000, End: 1999}},
		ExcludeUID:           []UIDRange{{Start: 1200, End: 1299}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !defaultBypass {
		t.Fatal("include policy did not enable default bypass")
	}
	for _, uid := range []uint32{1000, 1199, 1300, 1999} {
		if !uidMatchesPrefixes(uid, entries) {
			t.Fatalf("UID %d is not included", uid)
		}
	}
	for _, uid := range []uint32{999, 1200, 1299, 2000} {
		if uidMatchesPrefixes(uid, entries) {
			t.Fatalf("UID %d is unexpectedly included", uid)
		}
	}
}

func TestCompileEmptyConfiguredUIDPolicy(t *testing.T) {
	entries, defaultBypass, err := compileUIDPolicy(CgroupPolicy{IncludeUIDConfigured: true})
	if err != nil {
		t.Fatal(err)
	}
	if !defaultBypass || len(entries) != 0 {
		t.Fatalf("unexpected empty include policy: default_bypass=%v entries=%v", defaultBypass, entries)
	}
}

func TestCompileExcludeOnlyUIDPolicy(t *testing.T) {
	entries, defaultBypass, err := compileUIDPolicy(CgroupPolicy{
		ExcludeUID: []UIDRange{{Start: 1000, End: 1999}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if defaultBypass || !uidMatchesPrefixes(1500, entries) || uidMatchesPrefixes(2000, entries) {
		t.Fatalf("unexpected exclude policy: default_bypass=%v entries=%v", defaultBypass, entries)
	}
}

func TestCompileUIDPolicyExcludesAndroidDNSTetherDirectly(t *testing.T) {
	entries, defaultBypass, err := compileUIDPolicy(CgroupPolicy{
		ExcludeUID:              []UIDRange{{Start: androidDNSTetherUID, End: androidDNSTetherUID}},
		ExcludeAndroidDNSTether: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if defaultBypass || len(entries) != 0 {
		t.Fatalf("default Android policy still uses the UID map: default_bypass=%v entries=%v", defaultBypass, entries)
	}

	entries, defaultBypass, err = compileUIDPolicy(CgroupPolicy{
		ExcludeUID:              []UIDRange{{Start: 1000, End: 1100}},
		ExcludeAndroidDNSTether: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if defaultBypass {
		t.Fatal("exclude-only policy unexpectedly enables default bypass")
	}
	if uidMatchesPrefixes(1052, entries) {
		t.Fatal("directly excluded UID remained in the policy map")
	}
	for _, uid := range []uint32{1000, 1051, 1053, 1100} {
		if !uidMatchesPrefixes(uid, entries) {
			t.Fatalf("UID %d was removed with the directly excluded UID", uid)
		}
	}

	entries, defaultBypass, err = compileUIDPolicy(CgroupPolicy{
		IncludeUIDConfigured:    true,
		IncludeUID:              []UIDRange{{Start: 1000, End: 1100}},
		ExcludeAndroidDNSTether: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !defaultBypass || uidMatchesPrefixes(androidDNSTetherUID, entries) {
		t.Fatalf("unexpected include policy for Android dns_tether: default_bypass=%v entries=%v", defaultBypass, entries)
	}
}

func TestCompileBypassCIDRPolicy(t *testing.T) {
	ipv4, ipv6, err := compileBypassCIDRPolicy([]netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/9"),
		netip.MustParsePrefix("10.128.0.0/9"),
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("::ffff:192.0.2.0/120"),
		netip.MustParsePrefix("2001:db8::/33"),
		netip.MustParsePrefix("2001:db8:8000::/33"),
	})
	if err != nil {
		t.Fatal(err)
	}
	expectedIPv4 := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("192.0.2.0/24"),
	}
	expectedIPv6 := []netip.Prefix{netip.MustParsePrefix("2001:db8::/32")}
	if !equalPrefixes(ipv4, expectedIPv4) || !equalPrefixes(ipv6, expectedIPv6) {
		t.Fatalf("unexpected compiled CIDRs: IPv4=%v IPv6=%v", ipv4, ipv6)
	}
}

func TestBypassCIDRPolicyDelta(t *testing.T) {
	current := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("192.0.2.0/24"),
	}
	next := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("198.51.100.0/24"),
	}
	additions, removals := bypassCIDRPolicyDelta(current, next)
	if !equalPrefixes(additions, next[1:]) || !equalPrefixes(removals, current[1:]) {
		t.Fatalf("unexpected CIDR delta: additions=%v removals=%v", additions, removals)
	}
}

func equalPrefixes(left []netip.Prefix, right []netip.Prefix) bool {
	return slices.Equal(left, right)
}

func uidMatchesPrefixes(uid uint32, entries []uidLPMKey) bool {
	for _, entry := range entries {
		prefix := binary.BigEndian.Uint32(entry.UID[:])
		if entry.PrefixLength == 0 || uid>>(32-entry.PrefixLength) == prefix>>(32-entry.PrefixLength) {
			return true
		}
	}
	return false
}
