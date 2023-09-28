//go:build !with_randomaddr

package outbound

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

func NewRandomAddr(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.RandomAddrOutboundOptions) (adapter.Outbound, error) {
	return nil, E.New(`RandomAddr is not included in this build, rebuild with -tags with_randomaddr`)
}
