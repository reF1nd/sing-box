//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net"
	"testing"
	"time"
)

func TestRouteSourceIP(t *testing.T) {
	testCases := []struct {
		name     string
		source   any
		expected bool
	}{
		{
			name:     "IP global IPv6",
			source:   net.ParseIP("2001:db8::1"),
			expected: true,
		},
		{
			name:     "IPNet global IPv6",
			source:   &net.IPNet{IP: net.ParseIP("2001:db8::1")},
			expected: true,
		},
		{
			name:   "link-local IPv6",
			source: net.ParseIP("fe80::1"),
		},
		{
			name:   "IPv4",
			source: net.ParseIP("192.0.2.1"),
		},
		{
			name: "nil",
		},
		{
			name:   "typed nil IPNet",
			source: (*net.IPNet)(nil),
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			if actual := usableNativeIPv6(routeSourceIP(testCase.source)); actual != testCase.expected {
				t.Fatalf("unexpected result: got %v, want %v", actual, testCase.expected)
			}
		})
	}
}

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
