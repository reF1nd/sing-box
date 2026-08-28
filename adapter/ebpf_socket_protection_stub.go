//go:build !with_ebpf || (!linux && !android)

package adapter

import (
	"context"

	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
)

type EBPFSocketProtectionRegistration struct{}

func PrepareEBPFSocketProtection(context.Context) {}

func EBPFSocketProtectionControl(context.Context) control.Func { return nil }

func RegisterEBPFSocketProtection(_ context.Context, protectFunc control.Func) (*EBPFSocketProtectionRegistration, error) {
	if protectFunc == nil {
		return nil, E.New("socket protect function is nil")
	}
	return &EBPFSocketProtectionRegistration{}, nil
}

func (r *EBPFSocketProtectionRegistration) Close() {}
