//go:build with_ebpf && (linux || android)

package box

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/service"
)

func TestPrepareEBPFSocketProtection(t *testing.T) {
	for _, testCase := range []struct {
		name     string
		inbounds []option.Inbound
		prepared bool
	}{
		{"none", nil, false},
		{"unrelated", []option.Inbound{{Type: C.TypeDirect}}, false},
		{"default", []option.Inbound{ebpfInbound("")}, true},
		{"local", []option.Inbound{ebpfInbound("local")}, true},
		{"hybrid", []option.Inbound{ebpfInbound("hybrid")}, true},
		{"shared", []option.Inbound{ebpfInbound("shared")}, false},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			ctx := service.ContextWithDefaultRegistry(context.Background())
			prepareEBPFSocketProtection(ctx, testCase.inbounds)
			if prepared := adapter.EBPFSocketProtectionControl(ctx) != nil; prepared != testCase.prepared {
				t.Fatalf("unexpected preparation state: %v", prepared)
			}
		})
	}
}

func ebpfInbound(mode string) option.Inbound {
	return option.Inbound{Type: C.TypeEBPF, Options: &option.EBPFInboundOptions{Mode: mode}}
}
