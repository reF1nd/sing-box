//go:build with_ebpf && (linux || android)

package adapter

import (
	"context"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/sagernet/sing/service"
)

func TestEBPFSocketProtectionRegistration(t *testing.T) {
	ctx := service.ContextWithDefaultRegistry(context.Background())
	if EBPFSocketProtectionControl(ctx) != nil {
		t.Fatal("socket protection enabled before preparation")
	}
	PrepareEBPFSocketProtection(ctx)
	dynamicProtect := EBPFSocketProtectionControl(ctx)
	var calls atomic.Uint32
	registration, err := RegisterEBPFSocketProtection(ctx, func(string, string, syscall.RawConn) error {
		calls.Add(1)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = RegisterEBPFSocketProtection(ctx, func(string, string, syscall.RawConn) error { return nil }); err == nil {
		t.Fatal("accepted a second socket protect registration")
	}
	if err = dynamicProtect("udp", "1.1.1.1:53", nil); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("unexpected protect call count: %d", calls.Load())
	}
	registration.Close()
	if err = dynamicProtect("tcp", "example.com:443", nil); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatal("closed registration was still active")
	}
}

func TestEBPFSocketProtectionContextIsolation(t *testing.T) {
	firstContext := service.ContextWithDefaultRegistry(context.Background())
	secondContext := service.ContextWithDefaultRegistry(context.Background())
	PrepareEBPFSocketProtection(firstContext)
	PrepareEBPFSocketProtection(secondContext)
	first, err := RegisterEBPFSocketProtection(firstContext, func(string, string, syscall.RawConn) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := RegisterEBPFSocketProtection(secondContext, func(string, string, syscall.RawConn) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	second.Close()
}
