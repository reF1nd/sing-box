//go:build with_ebpf && (linux || android) && cgo

package ebpf

import "testing"

func TestSubtractCounter(t *testing.T) {
	testCases := []struct {
		value    uint64
		deleted  uint64
		expected uint64
	}{
		{value: 0, deleted: 0, expected: 0},
		{value: 10, deleted: 3, expected: 7},
		{value: 10, deleted: 10, expected: 0},
		{value: 10, deleted: 11, expected: 0},
	}
	for _, testCase := range testCases {
		actual := subtractCounter(testCase.value, testCase.deleted)
		if actual != testCase.expected {
			t.Fatalf(
				"subtractCounter(%d, %d): got %d, want %d",
				testCase.value,
				testCase.deleted,
				actual,
				testCase.expected,
			)
		}
	}
}

func TestRuntimeStatsABI(t *testing.T) {
	if statCount != 6 {
		t.Fatalf("unexpected native stats count: %d", statCount)
	}
}
