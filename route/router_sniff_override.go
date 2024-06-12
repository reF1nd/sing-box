package route

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
)

func (r *Router) matchSniffOverride(ctx context.Context, metadata *adapter.InboundContext) bool {
	rules := r.sniffOverrideRules[metadata.Inbound]
	if len(rules) == 0 {
		return true
	}
	defer metadata.ResetRuleCache()
	for i, rule := range rules {
		metadata.ResetRuleCache()
		if rule.Match(metadata) {
			r.overrideLogger.DebugContext(ctx, "match[", i, "] ", rule.String())
			return true
		}
	}
	return false
}
