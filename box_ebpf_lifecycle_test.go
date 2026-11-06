//go:build with_ebpf && (linux || android)

package box_test

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"testing"
	"time"

	commonEBPF "github.com/CHIZI-0618/sing-ebpf"
	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/internal/ebpfcleanup"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"
)

var errInjectedPlatformInitialize = errors.New("injected platform initialization failure")

type failingLifecyclePlatform struct {
	adapter.PlatformInterface
	networkManager adapter.NetworkManager
	selfBypass     *commonEBPF.SelfBypass
}

func (*failingLifecyclePlatform) UsePlatformDefaultInterfaceMonitor() bool { return false }
func (*failingLifecyclePlatform) UnderNetworkExtension() bool              { return false }
func (*failingLifecyclePlatform) UsePlatformConnectionOwnerFinder() bool   { return false }

func (p *failingLifecyclePlatform) Initialize(networkManager adapter.NetworkManager) error {
	p.networkManager = networkManager
	provider, loaded := networkManager.(interface {
		EBPFSelfBypass() *commonEBPF.SelfBypass
	})
	if loaded {
		p.selfBypass = provider.EBPFSelfBypass()
	}
	return errInjectedPlatformInitialize
}

func newLifecycleTestBox(t *testing.T) *box.Box {
	t.Helper()
	instance, err := box.New(box.Options{Context: include.Context(context.Background())})
	if err != nil {
		t.Fatal(err)
	}
	return instance
}

// A box that is created and closed without starting, as for a configuration
// check, must not leave eBPF goroutines or an unclaimed self-bypass behind.
func TestBoxCloseBeforeStartReleasesEBPF(t *testing.T) {
	ctx := include.Context(context.Background())
	var options option.Options
	err := json.UnmarshalContext(ctx, []byte(`{"log":{"disabled":true},"inbounds":[{"type":"ebpf","tag":"ebpf-in"}]}`), &options)
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		instance, err := box.New(box.Options{Context: ctx, Options: options})
		if err != nil {
			t.Fatal(err)
		}
		provider, loaded := instance.Network().(interface {
			EBPFSelfBypass() *commonEBPF.SelfBypass
		})
		if !loaded {
			t.Fatal("network manager does not expose eBPF self-bypass")
		}
		tracker := provider.EBPFSelfBypass()
		if tracker == nil {
			t.Fatal("eBPF self-bypass was not prepared")
		}
		if err = instance.Close(); err != nil {
			t.Fatal(err)
		}
		if !tracker.IsClosed() || provider.EBPFSelfBypass() != nil {
			t.Fatal("unclaimed eBPF self-bypass survived box close")
		}
	}
	deadline := time.Now().Add(time.Second)
	for {
		buffer := make([]byte, 1<<20)
		stacks := string(buffer[:runtime.Stack(buffer, true)])
		if !strings.Contains(stacks, "udpNATService).cleanupLoop") {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("eBPF UDP NAT cleanup goroutine leaked by a box that never started")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestBoxNewFailureReleasesPreparedSelfBypass(t *testing.T) {
	ctx := include.Context(context.Background())
	platform := new(failingLifecyclePlatform)
	service.MustRegister[adapter.PlatformInterface](ctx, platform)
	var options option.Options
	if err := json.UnmarshalContext(ctx, []byte(`{"inbounds":[{"type":"ebpf","tag":"ebpf-in"}]}`), &options); err != nil {
		t.Fatal(err)
	}
	if _, err := box.New(box.Options{Context: ctx, Options: options}); !errors.Is(err, errInjectedPlatformInitialize) {
		t.Fatalf("unexpected box construction error: %v", err)
	}
	if platform.selfBypass == nil {
		t.Fatal("platform initialization did not observe the prepared self-bypass")
	}
	if !platform.selfBypass.IsClosed() {
		t.Fatal("box construction failure left the prepared self-bypass open")
	}
	provider, loaded := platform.networkManager.(interface {
		EBPFSelfBypass() *commonEBPF.SelfBypass
	})
	if !loaded || provider.EBPFSelfBypass() != nil {
		t.Fatal("box construction failure left the self-bypass published")
	}
}

func TestBoxCloseRetriesRetainedEBPFResources(t *testing.T) {
	instance := newLifecycleTestBox(t)
	attempts := 0
	var entry *ebpfcleanup.Entry
	entry = ebpfcleanup.New(func() error {
		attempts++
		if attempts < 3 {
			return errors.New("injected cleanup failure")
		}
		ebpfcleanup.Release(entry)
		return nil
	})
	ebpfcleanup.Retain(entry)
	t.Cleanup(func() { ebpfcleanup.Release(entry) })
	if err := instance.Close(); err != nil {
		t.Fatal(err)
	}
	if attempts != 3 || ebpfcleanup.Contains(entry) {
		t.Fatalf("retained cleanup attempts=%d retained=%v", attempts, ebpfcleanup.Contains(entry))
	}
}

func TestBoxWithoutEBPFRefusesStaleResources(t *testing.T) {
	instance := newLifecycleTestBox(t)
	expected := errors.New("injected cleanup failure")
	attempts := 0
	entry := ebpfcleanup.New(func() error {
		attempts++
		return expected
	})
	ebpfcleanup.Retain(entry)
	t.Cleanup(func() { ebpfcleanup.Release(entry) })
	if err := instance.PreStart(); !errors.Is(err, expected) {
		t.Fatalf("unexpected pre-start error: %v", err)
	}
	// PreStart makes one safety check, then its failed-start Close performs the
	// bounded final retries even though this box has no eBPF inbound.
	if attempts != 1+3 || !ebpfcleanup.Contains(entry) {
		t.Fatalf("retained cleanup attempts=%d retained=%v", attempts, ebpfcleanup.Contains(entry))
	}
}
