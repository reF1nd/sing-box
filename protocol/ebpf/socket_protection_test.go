//go:build with_ebpf && (linux || android)

package ebpf

import "testing"

func TestSocketProtectorPendingCookies(t *testing.T) {
	protector := newSocketProtector()
	if err := protector.protectCookie(1); err != nil {
		t.Fatal(err)
	}
	if err := protector.protectCookie(1); err != nil {
		t.Fatal(err)
	}
	if len(protector.pending) != 1 {
		t.Fatalf("unexpected pending cookie count: %d", len(protector.pending))
	}
	protector.Close()
	if err := protector.protectCookie(2); err != nil {
		t.Fatal(err)
	}
}
