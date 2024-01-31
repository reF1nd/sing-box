//go:build !with_outbound_provider

package outboundprovider

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

func New(ctx context.Context, router adapter.Router, logFactory log.Factory, logger log.ContextLogger, tag string, options option.OutboundProvider) (adapter.OutboundProvider, error) {
	return nil, E.New(`OutboundProvider is not included in this build, rebuild with -tags with_outbound_provider`)
}
