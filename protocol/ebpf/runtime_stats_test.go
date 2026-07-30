//go:build with_ebpf && (linux || android)

package ebpf

import (
	"testing"

	ECommon "github.com/sagernet/sing-box/common/ebpf"
)

func TestRedirectMapWarningLevel(t *testing.T) {
	const capacity = uint64(ECommon.TCPRedirectMapCapacity)
	seventyFivePercent := (capacity*75 + 99) / 100
	ninetyPercent := (capacity*90 + 99) / 100
	testCases := []struct {
		entries  uint64
		expected int
	}{
		{0, 0},
		{seventyFivePercent - 1, 0},
		{seventyFivePercent, 75},
		{ninetyPercent - 1, 75},
		{ninetyPercent, 90},
		{capacity, 100},
	}
	for _, testCase := range testCases {
		if level := redirectMapWarningLevel(testCase.entries, capacity); level != testCase.expected {
			t.Errorf("unexpected warning level for %d entries: got %d, want %d", testCase.entries, level, testCase.expected)
		}
	}
}
