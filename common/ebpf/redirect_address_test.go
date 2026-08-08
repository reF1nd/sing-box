package ebpf

import (
	"net/netip"
	"testing"
)

func TestValidateRedirectPrefix(t *testing.T) {
	for _, prefix := range []string{
		"127.0.0.0/8",
		"127.128.0.0/9",
		"127.192.0.0/10",
		"fd53:696e:672d:626f::/64",
	} {
		if err := ValidateRedirectPrefix(netip.MustParsePrefix(prefix)); err != nil {
			t.Errorf("expected %s to be accepted: %v", prefix, err)
		}
	}
}

func TestValidateRedirectPrefixRejectsUnsafeRanges(t *testing.T) {
	for _, prefix := range []string{
		"10.0.0.0/8",
		"1.0.0.0/8",
		"127.0.0.0/7",
		"127.0.0.0/11",
		"2001:db8::/64",
		"fe80::/64",
		"fd53:696e:672d:626f::/96",
	} {
		if err := ValidateRedirectPrefix(netip.MustParsePrefix(prefix)); err == nil {
			t.Errorf("expected %s to be rejected", prefix)
		}
	}
}
