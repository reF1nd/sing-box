package rule

import (
	"context"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/service"
)

var _ RuleItem = (*ClashModeItem)(nil)

type ClashModeItem struct {
	ctx         context.Context
	clashServer adapter.ClashServer
	modes       []string
}

func NewClashModeItem(ctx context.Context, modes []string) *ClashModeItem {
	return &ClashModeItem{
		ctx:   ctx,
		modes: modes,
	}
}

func (r *ClashModeItem) Start() error {
	r.clashServer = service.FromContext[adapter.ClashServer](r.ctx)
	return nil
}

func (r *ClashModeItem) Match(metadata *adapter.InboundContext) bool {
	if r.clashServer == nil {
		return false
	}
	return common.Any(r.modes, func(mode string) bool {
		return strings.EqualFold(r.clashServer.Mode(), mode)
	})
}

func (r *ClashModeItem) String() string {
	modeStr := r.modes[0]
	if len(r.modes) > 1 {
		modeStr = "[" + strings.Join(r.modes, ", ") + "]"
	}
	return "clash_mode=" + modeStr
}
