//go:build !with_ebpf || (!linux && !android)

package box

import (
	"context"

	"github.com/sagernet/sing-box/option"
)

func prepareEBPFSocketProtection(context.Context, []option.Inbound) {}
