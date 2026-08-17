//go:build with_ebpf && (linux || android)

package ebpf

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestRuntimeProgramStatusUnavailable(t *testing.T) {
	status := runtimeProgramStatus(nil, "test", "classifier/test")
	if status.Loaded || status.Attached || status.Name != "test" || status.Section != "classifier/test" {
		t.Fatalf("unexpected unavailable program status: %+v", status)
	}
}

func TestCountMapEntriesEfficientRejectsInvalidLayout(t *testing.T) {
	var support mapBatchSupport
	if _, err := countMapEntriesEfficient(-1, 0, 4, 1, &support); err != unix.EINVAL {
		t.Fatalf("unexpected invalid layout error: %v", err)
	}
}
