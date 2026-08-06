//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"testing"
	"unsafe"
)

var (
	_ [56 - unsafe.Sizeof(mapBatchAttr{})]byte
	_ [unsafe.Sizeof(mapBatchAttr{}) - 56]byte
)

func TestMapBatchAttrABI(t *testing.T) {
	attribute := mapBatchAttr{}
	if size := unsafe.Sizeof(attribute); size != 56 {
		t.Fatalf("unexpected batch map attribute size: %d", size)
	}
	for name, offset := range map[string]uintptr{
		"in_batch":   unsafe.Offsetof(attribute.InBatch),
		"out_batch":  unsafe.Offsetof(attribute.OutBatch),
		"keys":       unsafe.Offsetof(attribute.Keys),
		"values":     unsafe.Offsetof(attribute.Values),
		"count":      unsafe.Offsetof(attribute.Count),
		"map_fd":     unsafe.Offsetof(attribute.MapFD),
		"elem_flags": unsafe.Offsetof(attribute.ElemFlags),
		"flags":      unsafe.Offsetof(attribute.Flags),
	} {
		expected := map[string]uintptr{
			"in_batch": 0, "out_batch": 8, "keys": 16, "values": 24,
			"count": 32, "map_fd": 36, "elem_flags": 40, "flags": 48,
		}[name]
		if offset != expected {
			t.Fatalf("unexpected %s offset: %d", name, offset)
		}
	}
}

func TestValidateMapCapacity(t *testing.T) {
	if err := validateMapCapacity("test", 1); err != nil {
		t.Fatal(err)
	}
	if err := validateMapCapacity("test", 0); err == nil {
		t.Fatal("expected zero capacity to fail")
	}
	if err := validateMapCapacity("test", MaxConfigurableMapCapacity+1); err == nil {
		t.Fatal("expected oversized capacity to fail")
	}
}

func TestBackendHealth(t *testing.T) {
	var health backendHealth
	if err := health.requireUsable(true); err != nil {
		t.Fatal(err)
	}
	invalidateErr := health.invalidate("test", "policy")
	if invalidateErr == nil {
		t.Fatal("expected invalidation error")
	}
	if err := health.requireUsable(true); !errors.Is(err, invalidateErr) {
		t.Fatalf("unexpected health error: %v", err)
	}
	if err := health.requireUsable(false); !errors.Is(err, errBackendClosed) {
		t.Fatalf("expected closed backend error, got %v", err)
	}
}

func TestPolicyUpdateError(t *testing.T) {
	updateErr := errors.New("update")
	rollbackErr := errors.New("rollback")
	if err := policyUpdateError(updateErr, nil); !errors.Is(err, updateErr) {
		t.Fatalf("unexpected update error: %v", err)
	}
	err := policyUpdateError(updateErr, rollbackErr)
	if !policyRollbackFailed(err) {
		t.Fatal("expected rollback failure marker")
	}
	if !errors.Is(err, updateErr) || !errors.Is(err, rollbackErr) {
		t.Fatalf("transaction error did not preserve causes: %v", err)
	}
}
