//go:build with_ebpf && (linux || android)

package ebpf

import (
	"testing"
	"time"
)

func TestCgroupIPv6ProbeDebounceAndCancellation(t *testing.T) {
	originalDebounce := cgroupIPv6ProbeDebounce
	originalProbe := probeCgroupIPv6AvailableFunc
	t.Cleanup(func() {
		cgroupIPv6ProbeDebounce = originalDebounce
		probeCgroupIPv6AvailableFunc = originalProbe
	})
	cgroupIPv6ProbeDebounce = 5 * time.Millisecond
	probes := make(chan struct{}, 2)
	probeCgroupIPv6AvailableFunc = func() (bool, error) {
		probes <- struct{}{}
		return true, nil
	}

	inbound := &Inbound{cgroupIPv6Available: true}
	inbound.lifecycleAccess.Lock()
	inbound.scheduleCgroupIPv6ProbeLocked()
	inbound.scheduleCgroupIPv6ProbeLocked()
	inbound.lifecycleAccess.Unlock()
	select {
	case <-probes:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("debounced IPv6 probe did not run")
	}
	inbound.lifecycleAccess.Lock()
	inbound.lifecycleAccess.Unlock()
	select {
	case <-probes:
		t.Fatal("superseded IPv6 probe was not canceled")
	case <-time.After(20 * time.Millisecond):
	}

	inbound.lifecycleAccess.Lock()
	inbound.scheduleCgroupIPv6ProbeLocked()
	inbound.resetCgroupIPv6ProbeLocked()
	inbound.lifecycleAccess.Unlock()
	select {
	case <-probes:
		t.Fatal("canceled IPv6 probe ran after reset")
	case <-time.After(20 * time.Millisecond):
	}
}
