//go:build !with_ebpf || (!linux && !android)

package include

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

func registerEBPFInbound(registry *inbound.Registry) {
	inbound.Register[option.EBPFInboundOptions](registry, C.TypeEBPF, func(context.Context, adapter.Router, log.ContextLogger, string, option.EBPFInboundOptions) (adapter.Inbound, error) {
		return nil, E.New("eBPF inbound is not included in this build")
	})
}
