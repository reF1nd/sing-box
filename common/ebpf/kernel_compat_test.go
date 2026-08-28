//go:build with_ebpf && (linux || android)

package ebpf

import "testing"

func TestKnownUnsafeLPMTrieRelease(t *testing.T) {
	t.Parallel()
	for _, testCase := range []struct {
		release string
		unsafe  bool
	}{
		{"6.6.0", true},
		{"6.6.30-android15-8-g9d08353fa520-abogki", true},
		{"6.6.46+", true},
		{"6.6.47", false},
		{"6.6.99-vendor", false},
		{"6.1.107", false},
		{"5.15.165-android14", false},
		{"6.6", false},
		{"unknown", false},
	} {
		testCase := testCase
		t.Run(testCase.release, func(t *testing.T) {
			t.Parallel()
			if unsafe := knownUnsafeLPMTrieRelease(testCase.release); unsafe != testCase.unsafe {
				t.Fatalf("unsafe=%v, want %v", unsafe, testCase.unsafe)
			}
		})
	}
}
