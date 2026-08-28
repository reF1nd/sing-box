//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net/netip"
	"testing"
)

func TestUserspaceReplyToken(t *testing.T) {
	testCases := []netip.Prefix{
		netip.MustParsePrefix("127.128.0.0/9"),
		netip.MustParsePrefix("fd53:696e:672d:626f::/64"),
	}
	for _, prefix := range testCases {
		t.Run(prefix.String(), func(t *testing.T) {
			first, valid := userspaceReplyToken(prefix, 1)
			if !valid || !prefix.Contains(first) {
				t.Fatalf("invalid first token: %v, valid=%v", first, valid)
			}
			second, valid := userspaceReplyToken(prefix, 2)
			if !valid || !prefix.Contains(second) || second == first {
				t.Fatalf("invalid second token: %v, valid=%v", second, valid)
			}
		})
	}
}
