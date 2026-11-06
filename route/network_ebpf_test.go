//go:build with_ebpf && (linux || android)

package route

import (
	"sync"
	"testing"

	commonEBPF "github.com/CHIZI-0618/sing-ebpf"
)

func TestCloseUnclaimedEBPFSelfBypass(t *testing.T) {
	for _, claimed := range []bool{false, true} {
		tracker, err := commonEBPF.NewSelfBypass()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = tracker.Close() })
		manager := &NetworkManager{}
		if err = manager.SetEBPFSelfBypass(tracker); err != nil {
			t.Fatal(err)
		}
		if claimed && !manager.ClaimEBPFSelfBypass(tracker) {
			t.Fatal("claim of the configured tracker failed")
		}
		if err = manager.CloseUnclaimedEBPFSelfBypass(); err != nil {
			t.Fatal(err)
		}
		if claimed {
			if tracker.IsClosed() || manager.EBPFSelfBypass() != tracker {
				t.Fatal("box closed a self-bypass owned by an inbound")
			}
		} else if !tracker.IsClosed() || manager.EBPFSelfBypass() != nil {
			t.Fatal("unclaimed self-bypass was not closed")
		}
	}
}

func TestClaimAfterUnclaimedCloseFails(t *testing.T) {
	tracker, err := commonEBPF.NewSelfBypass()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tracker.Close() })
	manager := &NetworkManager{}
	if err = manager.SetEBPFSelfBypass(tracker); err != nil {
		t.Fatal(err)
	}
	if err = manager.CloseUnclaimedEBPFSelfBypass(); err != nil {
		t.Fatal(err)
	}
	if manager.ClaimEBPFSelfBypass(tracker) {
		t.Fatal("claimed a tracker the box already closed")
	}
}

// Exactly one side owns the tracker however a claim and the box fallback
// interleave: a successful claim keeps it open, otherwise the box closes it.
func TestConcurrentClaimAndUnclaimedClose(t *testing.T) {
	for range 200 {
		tracker, err := commonEBPF.NewSelfBypass()
		if err != nil {
			t.Fatal(err)
		}
		manager := &NetworkManager{}
		if err = manager.SetEBPFSelfBypass(tracker); err != nil {
			t.Fatal(err)
		}
		var claimed bool
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			claimed = manager.ClaimEBPFSelfBypass(tracker)
		}()
		go func() {
			defer wg.Done()
			_ = manager.CloseUnclaimedEBPFSelfBypass()
		}()
		wg.Wait()
		if claimed == tracker.IsClosed() {
			t.Fatalf("claimed=%v but tracker closed=%v", claimed, tracker.IsClosed())
		}
		_ = tracker.Close()
	}
}
