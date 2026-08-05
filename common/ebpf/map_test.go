//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"testing"
)

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
