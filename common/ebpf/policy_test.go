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
