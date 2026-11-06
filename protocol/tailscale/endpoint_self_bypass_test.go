//go:build with_gvisor

package tailscale

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/sagernet/tailscale/net/netmon"
	"github.com/sagernet/tailscale/net/netns"
	"github.com/sagernet/tailscale/types/nettype"
)

type selfBypassTestPacketConn struct {
	nettype.PacketConn
	cleanupCount *atomic.Int32
	closedEarly  atomic.Bool
}

func (c *selfBypassTestPacketConn) Close() error {
	if c.cleanupCount.Load() != 1 {
		c.closedEarly.Store(true)
	}
	return net.ErrClosed
}

func TestSelfBypassPacketConnCleanupBeforeClose(t *testing.T) {
	var cleanupCount atomic.Int32
	underlying := &selfBypassTestPacketConn{cleanupCount: &cleanupCount}
	conn := &selfBypassPacketConn{PacketConn: underlying, cleanup: func() { cleanupCount.Add(1) }}
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			if err := conn.Close(); err != net.ErrClosed {
				t.Errorf("close error not preserved: %v", err)
			}
		})
	}
	workers.Wait()
	if cleanupCount.Load() != 1 || underlying.closedEarly.Load() {
		t.Fatal("socket cleanup must run exactly once before closing the underlying socket")
	}
}

func TestTailscaleGlobalHooksOwnershipAcrossReplaceAndRollback(t *testing.T) {
	// Hot-replace success: new endpoint registers before old endpoint closes.
	// Closing old endpoint must leave new endpoint's netmon and netns hooks active.
	var oldControlCalls, newControlCalls atomic.Int32
	var oldListenCalls, newListenCalls atomic.Int32

	oldUnregNetmon := registerGlobalNetmonHooks(
		func() ([]netmon.Interface, error) {
			return []netmon.Interface{{Interface: &net.Interface{Name: "old0", Index: 1}}}, nil
		},
		func() (netmon.DefaultRouteDetails, error) {
			return netmon.DefaultRouteDetails{InterfaceName: "old0", InterfaceIndex: 1}, nil
		},
	)
	oldUnregNetns := registerGlobalNetnsHooks(
		func(string, string, syscall.RawConn) error {
			oldControlCalls.Add(1)
			return nil
		},
		func(context.Context, string, string) (nettype.PacketConn, error) {
			oldListenCalls.Add(1)
			return nil, net.ErrClosed
		},
	)
	t.Cleanup(func() {
		oldUnregNetns()
		oldUnregNetmon()
	})

	// Candidate starts and installs hooks on top of old endpoint.
	candUnregNetmon := registerGlobalNetmonHooks(
		func() ([]netmon.Interface, error) {
			return []netmon.Interface{{Interface: &net.Interface{Name: "cand0", Index: 2}}}, nil
		},
		func() (netmon.DefaultRouteDetails, error) {
			return netmon.DefaultRouteDetails{InterfaceName: "cand0", InterfaceIndex: 2}, nil
		},
	)
	candUnregNetns := registerGlobalNetnsHooks(
		func(string, string, syscall.RawConn) error {
			newControlCalls.Add(1)
			return nil
		},
		func(context.Context, string, string) (nettype.PacketConn, error) {
			newListenCalls.Add(1)
			return nil, net.ErrClosed
		},
	)

	// Case 1: Candidate fails PostStart and rolls back; old endpoint's hooks must be restored.
	candUnregNetns()
	candUnregNetmon()

	netMon := netmon.NewStatic()
	route, err := netmon.DefaultRoute()
	if err != nil || route.InterfaceName != "old0" {
		t.Fatalf("after candidate rollback, DefaultRoute() = (%+v, %v), want old0", route, err)
	}
	if err = netns.Listener(t.Logf, netMon).Control("udp4", "127.0.0.1:0", nil); err != nil {
		t.Fatalf("after candidate rollback, control hook failed: %v", err)
	}
	if oldControlCalls.Load() != 1 {
		t.Fatalf("expected old control hook to be restored, calls=%d", oldControlCalls.Load())
	}
	listenFn := netns.ListenPacketFunc()
	if listenFn == nil {
		t.Fatal("after candidate rollback, ListenPacketFunc() is nil")
	}
	if _, err = listenFn(context.Background(), "udp4", "127.0.0.1:0"); err != net.ErrClosed {
		t.Fatalf("after candidate rollback, expected old listenPacket hook err=%v", err)
	}
	if oldListenCalls.Load() != 1 {
		t.Fatalf("expected old listenPacket hook to be restored, calls=%d", oldListenCalls.Load())
	}

	// Case 2: Replacement succeeds: new endpoint installs hooks, then old endpoint closes.
	newUnregNetmon := registerGlobalNetmonHooks(
		func() ([]netmon.Interface, error) {
			return []netmon.Interface{{Interface: &net.Interface{Name: "new0", Index: 3}}}, nil
		},
		func() (netmon.DefaultRouteDetails, error) {
			return netmon.DefaultRouteDetails{InterfaceName: "new0", InterfaceIndex: 3}, nil
		},
	)
	newUnregNetns := registerGlobalNetnsHooks(
		func(string, string, syscall.RawConn) error {
			newControlCalls.Add(1)
			return nil
		},
		func(context.Context, string, string) (nettype.PacketConn, error) {
			newListenCalls.Add(1)
			return nil, net.ErrClosed
		},
	)
	t.Cleanup(func() {
		newUnregNetns()
		newUnregNetmon()
	})

	// Old endpoint closes after replacement succeeded.
	oldUnregNetns()
	oldUnregNetmon()

	route, err = netmon.DefaultRoute()
	if err != nil || route.InterfaceName != "new0" {
		t.Fatalf("after old endpoint close, DefaultRoute() = (%+v, %v), want new0", route, err)
	}
	if err = netns.Listener(t.Logf, netMon).Control("udp4", "127.0.0.1:0", nil); err != nil {
		t.Fatalf("after old endpoint close, control hook failed: %v", err)
	}
	if newControlCalls.Load() != 1 {
		t.Fatalf("expected new control hook to remain active, calls=%d", newControlCalls.Load())
	}
	listenFn = netns.ListenPacketFunc()
	if listenFn == nil {
		t.Fatal("after old endpoint close, ListenPacketFunc() is nil")
	}
	if _, err = listenFn(context.Background(), "udp4", "127.0.0.1:0"); err != net.ErrClosed {
		t.Fatalf("after old endpoint close, expected new listenPacket hook err=%v", err)
	}
	if newListenCalls.Load() != 1 {
		t.Fatalf("expected new listenPacket hook to remain active, calls=%d", newListenCalls.Load())
	}

	// Closing the last surviving endpoint clears the stacks cleanly and falls back
	// to system interface enumeration.
	newUnregNetns()
	newUnregNetmon()
	if netns.ListenPacketFunc() != nil {
		t.Fatal("expected ListenPacketFunc() to be nil after all endpoints close")
	}
	globalHookAccess.Lock()
	netmonLen := len(globalNetmonHookStack)
	netnsLen := len(globalNetnsHookStack)
	globalHookAccess.Unlock()
	if netmonLen != 0 || netnsLen != 0 {
		t.Fatalf("expected empty hook stacks after all endpoints close, got netmon=%d netns=%d", netmonLen, netnsLen)
	}
	sysIfaces, err := netmon.GetInterfaceList()
	if err != nil || len(sysIfaces) == 0 {
		t.Fatalf("expected system interface enumeration after all endpoints close, got (%d, %v)", len(sysIfaces), err)
	}

	// Concurrent GetInterfaceList / DefaultRoute enumeration during repeated
	// hot-replace and candidate rollback must be data-race-free.
	stopReaders := make(chan struct{})
	var readers sync.WaitGroup
	for range 4 {
		readers.Go(func() {
			for {
				select {
				case <-stopReaders:
					return
				default:
					_, _ = netmon.GetInterfaceList()
					_, _ = netmon.DefaultRoute()
					_ = netns.ListenPacketFunc()
				}
			}
		})
	}
	for range 32 {
		u1m := registerGlobalNetmonHooks(
			func() ([]netmon.Interface, error) {
				return []netmon.Interface{{Interface: &net.Interface{Name: "r1", Index: 11}}}, nil
			},
			func() (netmon.DefaultRouteDetails, error) {
				return netmon.DefaultRouteDetails{InterfaceName: "r1", InterfaceIndex: 11}, nil
			},
		)
		u1n := registerGlobalNetnsHooks(nil, nil)
		// Candidate rollback
		uCandM := registerGlobalNetmonHooks(
			func() ([]netmon.Interface, error) {
				return []netmon.Interface{{Interface: &net.Interface{Name: "rc", Index: 12}}}, nil
			},
			func() (netmon.DefaultRouteDetails, error) {
				return netmon.DefaultRouteDetails{InterfaceName: "rc", InterfaceIndex: 12}, nil
			},
		)
		uCandN := registerGlobalNetnsHooks(nil, nil)
		uCandN()
		uCandM()
		// Replacement success (old closes after new registers)
		u2m := registerGlobalNetmonHooks(
			func() ([]netmon.Interface, error) {
				return []netmon.Interface{{Interface: &net.Interface{Name: "r2", Index: 13}}}, nil
			},
			func() (netmon.DefaultRouteDetails, error) {
				return netmon.DefaultRouteDetails{InterfaceName: "r2", InterfaceIndex: 13}, nil
			},
		)
		u2n := registerGlobalNetnsHooks(nil, nil)
		u1n()
		u1m()
		u2n()
		u2m()
	}
	close(stopReaders)
	readers.Wait()
}
