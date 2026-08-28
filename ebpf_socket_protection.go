//go:build with_ebpf && (linux || android)

package box

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

func prepareEBPFSocketProtection(ctx context.Context, inbounds []option.Inbound) {
	for _, inbound := range inbounds {
		if inbound.Type != C.TypeEBPF {
			continue
		}
		ebpfOptions, loaded := inbound.Options.(*option.EBPFInboundOptions)
		if !loaded || ebpfOptions.Mode != "shared" {
			adapter.PrepareEBPFSocketProtection(ctx)
			return
		}
	}
}
