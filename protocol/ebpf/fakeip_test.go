//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net/netip"
	"testing"
)

func TestNormalizeFakeIPPrefixes(t *testing.T) {
	inbound := &Inbound{
		fakeIPIPv4Prefix: netip.MustParsePrefix("198.18.1.1/15"),
		fakeIPIPv6Prefix: netip.MustParsePrefix("fc00::1/18"),
	}
	if err := inbound.normalizeFakeIPPrefixes(); err != nil {
		t.Fatal(err)
	}
	if inbound.fakeIPIPv4Prefix != netip.MustParsePrefix("198.18.0.0/15") {
		t.Fatalf("unexpected normalized IPv4 FakeIP range: %s", inbound.fakeIPIPv4Prefix)
	}
	if inbound.fakeIPIPv6Prefix != netip.MustParsePrefix("fc00::/18") {
		t.Fatalf("unexpected normalized IPv6 FakeIP range: %s", inbound.fakeIPIPv6Prefix)
	}
}

func TestNormalizeFakeIPPrefixesRejectsSafetyOverlap(t *testing.T) {
	for _, test := range []struct {
		name string
		ipv4 string
		ipv6 string
	}{
		{name: "IPv4 unspecified", ipv4: "0.0.0.0/8"},
		{name: "IPv4 loopback", ipv4: "127.128.0.0/9"},
		{name: "IPv4 multicast", ipv4: "239.0.0.0/8"},
		{name: "IPv6 unspecified", ipv6: "::/128"},
		{name: "IPv6 loopback", ipv6: "::1/128"},
		{name: "IPv6 reserved compatibility", ipv6: "::ff00:0:0/104"},
		{name: "IPv6 multicast", ipv6: "ff02::/16"},
	} {
		t.Run(test.name, func(t *testing.T) {
			inbound := &Inbound{}
			if test.ipv4 != "" {
				inbound.fakeIPIPv4Prefix = netip.MustParsePrefix(test.ipv4)
			}
			if test.ipv6 != "" {
				inbound.fakeIPIPv6Prefix = netip.MustParsePrefix(test.ipv6)
			}
			if err := inbound.normalizeFakeIPPrefixes(); err == nil {
				t.Fatal("expected unsafe FakeIP range to be rejected")
			}
		})
	}
}
