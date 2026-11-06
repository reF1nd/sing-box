package ebpfcleanup

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
)

func TestRetryReleasesWithoutHoldingRegistry(t *testing.T) {
	var entry *Entry
	entry = New(func() error {
		Release(entry)
		return nil
	})
	Retain(entry)
	Retain(entry)
	if err := Retry(); err != nil {
		t.Fatal(err)
	}
	if Contains(entry) {
		t.Fatal("successful cleanup remained retained")
	}
}

func TestRetryKeepsFailedCleanup(t *testing.T) {
	expected := errors.New("injected cleanup failure")
	entry := New(func() error { return expected })
	Retain(entry)
	t.Cleanup(func() { Release(entry) })
	if err := Retry(); !errors.Is(err, expected) {
		t.Fatalf("unexpected retry error: %v", err)
	}
	if !Contains(entry) {
		t.Fatal("failed cleanup was released")
	}
}

func TestConcurrentRetainAndRetry(t *testing.T) {
	var attempts atomic.Uint64
	entry := New(func() error {
		attempts.Add(1)
		return nil
	})
	Retain(entry)
	defer Release(entry)
	var waitGroup sync.WaitGroup
	for range 100 {
		waitGroup.Add(2)
		go func() {
			defer waitGroup.Done()
			Retain(entry)
		}()
		go func() {
			defer waitGroup.Done()
			_ = Retry()
		}()
	}
	waitGroup.Wait()
	if attempts.Load() == 0 {
		t.Fatal("retained cleanup was never retried")
	}
}
