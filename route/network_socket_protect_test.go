package route

import (
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/sagernet/sing-box/adapter"
)

func TestDynamicSocketProtectFunc(t *testing.T) {
	manager := new(NetworkManager)
	protect := adapter.SocketProtectFunc(manager)
	if err := protect("tcp4", "example.com:443", nil); err != nil {
		t.Fatal(err)
	}

	var called atomic.Int32
	if err := manager.RegisterSocketProtectFunc(func(string, string, syscall.RawConn) error {
		called.Add(1)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := protect("tcp4", "example.com:443", nil); err != nil {
		t.Fatal(err)
	}
	if called.Load() != 1 {
		t.Fatalf("unexpected protector call count: %d", called.Load())
	}

	if err := manager.RegisterSocketProtectFunc(func(string, string, syscall.RawConn) error { return nil }); err == nil {
		t.Fatal("expected duplicate protector registration to fail")
	}
	manager.UnregisterSocketProtectFunc()
	if err := protect("tcp4", "example.com:443", nil); err != nil {
		t.Fatal(err)
	}
	if called.Load() != 1 {
		t.Fatalf("protector called after unregister: %d", called.Load())
	}
}
