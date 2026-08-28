//go:build with_ebpf && (linux || android)

package adapter

import (
	"context"
	"sync/atomic"
	"syscall"

	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/service"
)

type EBPFSocketProtectionRegistration struct {
	protectFunc control.Func
	service     *ebpfSocketProtectionService
}

type ebpfSocketProtectionService struct {
	registration atomic.Pointer[EBPFSocketProtectionRegistration]
	control      control.Func
}

func PrepareEBPFSocketProtection(ctx context.Context) {
	if service.FromContext[*ebpfSocketProtectionService](ctx) != nil {
		return
	}
	protectService := new(ebpfSocketProtectionService)
	protectService.control = func(network string, address string, conn syscall.RawConn) error {
		registration := protectService.registration.Load()
		if registration == nil {
			return nil
		}
		return registration.protectFunc(network, address, conn)
	}
	service.MustRegister[*ebpfSocketProtectionService](ctx, protectService)
}

func EBPFSocketProtectionControl(ctx context.Context) control.Func {
	protectService := service.FromContext[*ebpfSocketProtectionService](ctx)
	if protectService == nil {
		return nil
	}
	return protectService.control
}

func RegisterEBPFSocketProtection(ctx context.Context, protectFunc control.Func) (*EBPFSocketProtectionRegistration, error) {
	if protectFunc == nil {
		return nil, E.New("socket protect function is nil")
	}
	protectService := service.FromContext[*ebpfSocketProtectionService](ctx)
	if protectService == nil {
		return nil, E.New("socket protection service is not prepared")
	}
	registration := &EBPFSocketProtectionRegistration{protectFunc: protectFunc, service: protectService}
	if !protectService.registration.CompareAndSwap(nil, registration) {
		return nil, E.New("a socket protect function is already registered")
	}
	return registration, nil
}

func (r *EBPFSocketProtectionRegistration) Close() {
	if r != nil {
		r.service.registration.CompareAndSwap(r, nil)
	}
}
