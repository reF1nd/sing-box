//go:build with_ebpf && (linux || android)

package ebpf

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestWarningLimiter(t *testing.T) {
	var limiter warningLimiter
	baseTime := time.Unix(1, 0)
	allowed, suppressed := limiter.allow(baseTime)
	if !allowed || suppressed != 0 {
		t.Fatalf("unexpected first result: allowed=%v suppressed=%d", allowed, suppressed)
	}
	allowed, suppressed = limiter.allow(baseTime.Add(packetWarningInterval / 2))
	if allowed || suppressed != 0 {
		t.Fatalf("unexpected limited result: allowed=%v suppressed=%d", allowed, suppressed)
	}
	allowed, suppressed = limiter.allow(baseTime.Add(packetWarningInterval))
	if !allowed || suppressed != 1 {
		t.Fatalf("unexpected resumed result: allowed=%v suppressed=%d", allowed, suppressed)
	}
}

func TestWarningLimiterConcurrent(t *testing.T) {
	const attempts = 32
	var limiter warningLimiter
	var allowedCount atomic.Uint32
	baseTime := time.Unix(1, 0)
	var group sync.WaitGroup
	for range attempts {
		group.Add(1)
		go func() {
			defer group.Done()
			if allowed, _ := limiter.allow(baseTime); allowed {
				allowedCount.Add(1)
			}
		}()
	}
	group.Wait()
	if allowedCount.Load() != 1 {
		t.Fatalf("unexpected concurrent allowance count: %d", allowedCount.Load())
	}
	allowed, suppressed := limiter.allow(baseTime.Add(packetWarningInterval))
	if !allowed || suppressed != attempts-1 {
		t.Fatalf("unexpected suppression summary: allowed=%v suppressed=%d", allowed, suppressed)
	}
}

func TestWarningLimitersAreIndependent(t *testing.T) {
	var first warningLimiter
	var second warningLimiter
	baseTime := time.Unix(1, 0)
	first.allow(baseTime)
	if allowed, _ := first.allow(baseTime); allowed {
		t.Fatal("first limiter did not limit a repeated warning")
	}
	if allowed, suppressed := second.allow(baseTime); !allowed || suppressed != 0 {
		t.Fatalf("second limiter inherited state: allowed=%v suppressed=%d", allowed, suppressed)
	}
}
