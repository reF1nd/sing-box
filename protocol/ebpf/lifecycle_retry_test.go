//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/internal/ebpfcleanup"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
)

func retainedInboundsContain(inbound *Inbound) bool {
	return ebpfcleanup.Contains(inbound.retainedCleanupEntry())
}

type retainingSharedRuntime struct {
	testSharedKernelRuntime
	failures int
	attempts int
	// When set, the first Close signals entered and waits for release.
	entered chan struct{}
	release chan struct{}
}

func (r *retainingSharedRuntime) Close() error {
	r.attempts++
	if r.attempts == 1 && r.release != nil {
		close(r.entered)
		<-r.release
	}
	if r.attempts <= r.failures {
		return errors.New("injected detach failure")
	}
	r.closed = true
	return nil
}

func newRetainingTestInbound(failures int) (*Inbound, *retainingSharedRuntime) {
	inbound := &Inbound{ctx: context.Background(), udpTimeout: time.Minute}
	inbound.udpNat = newUDPNATService(inbound, inbound.preparePacketConnection, time.Minute)
	shared := newSharedRewrite(inbound, option.EBPFSharedOptions{})
	runtime := &retainingSharedRuntime{failures: failures}
	shared.setDataPlane(runtime)
	inbound.setSharedRewrite(shared)
	return inbound, runtime
}

// The adapter scope runs a cleanup once, so an inbound whose Close keeps
// resources must be retried by the next eBPF inbound before it starts.
func TestRetainedInboundRetriedBeforeNextStart(t *testing.T) {
	old, runtime := newRetainingTestInbound(1)
	t.Cleanup(func() { _ = old.Close() })
	if err := old.Close(); err == nil {
		t.Fatal("injected failure was not propagated")
	}
	if !retainedInboundsContain(old) {
		t.Fatal("inbound with retained resources was not recorded for retry")
	}
	next := &Inbound{logger: log.NewNOPFactory().NewLogger("ebpf")}
	scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
	t.Cleanup(func() { _ = scope.Close() })
	if err := next.Start(adapter.StartStateInitialize, scope); err != nil {
		t.Fatal(err)
	}
	if !runtime.closed || retainedInboundsContain(old) {
		t.Fatal("retained resources were not released before the next start")
	}
}

func TestStartFailsWhileRetainedResourcesRemain(t *testing.T) {
	old, _ := newRetainingTestInbound(2)
	t.Cleanup(func() {
		_ = old.Close()
		_ = old.Close()
	})
	if err := old.Close(); err == nil {
		t.Fatal("injected failure was not propagated")
	}
	next := &Inbound{logger: log.NewNOPFactory().NewLogger("ebpf")}
	scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
	t.Cleanup(func() { _ = scope.Close() })
	if err := next.Start(adapter.StartStateInitialize, scope); err == nil {
		t.Fatal("started while stale eBPF resources were still attached")
	}
	if !retainedInboundsContain(old) {
		t.Fatal("inbound was dropped from the retry list while resources remain")
	}
}

// A Close still releasing resources must be waited for: the next inbound would
// otherwise pass its retry check and attach while those resources remain.
func TestStartWaitsForInProgressClose(t *testing.T) {
	old, runtime := newRetainingTestInbound(1)
	runtime.entered = make(chan struct{})
	runtime.release = make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(runtime.release) }) }
	t.Cleanup(func() { _ = old.Close() })
	t.Cleanup(release)
	closeDone := make(chan error, 1)
	go func() { closeDone <- old.Close() }()
	<-runtime.entered
	next := &Inbound{logger: log.NewNOPFactory().NewLogger("ebpf")}
	scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
	t.Cleanup(func() { _ = scope.Close() })
	startDone := make(chan error, 1)
	go func() { startDone <- next.Start(adapter.StartStateInitialize, scope) }()
	select {
	case err := <-startDone:
		t.Fatalf("initialized while a previous Close was still releasing resources: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	release()
	if err := <-closeDone; err == nil {
		t.Fatal("injected failure was not propagated")
	}
	if err := <-startDone; err != nil {
		t.Fatal(err)
	}
	if !runtime.closed || retainedInboundsContain(old) {
		t.Fatal("resources retained by the in-progress Close were not released before the next start")
	}
}

func TestIdleUDPNATServiceStartsOnce(t *testing.T) {
	service := newIdleUDPNATService(nil, nil, time.Minute)
	if service.started {
		t.Fatal("idle service started its cleanup goroutine")
	}
	service.start()
	service.start()
	if !service.started {
		t.Fatal("service did not start")
	}
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
	closed := newIdleUDPNATService(nil, nil, time.Minute)
	if err := closed.Close(); err != nil {
		t.Fatal(err)
	}
	closed.start()
	if closed.started {
		t.Fatal("closed service started its cleanup goroutine")
	}
}
