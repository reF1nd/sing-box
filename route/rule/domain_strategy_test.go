package rule

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

func TestLogicalDomainMatchStrategyInheritance(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		var childStrategy option.DomainMatchStrategy
		domain := "destination.example"
		if explicit {
			childStrategy = option.DomainMatchStrategy(C.DomainMatchStrategySniffHostOnly)
			domain = "sniff.example"
		}
		metadata := adapter.InboundContext{Destination: M.ParseSocksaddr("destination.example:443"), SniffHost: "sniff.example"}
		rule, err := NewLogicalRule(context.Background(), logger.NOP(), option.LogicalRule{RawLogicalRule: option.RawLogicalRule{
			Mode: C.LogicalTypeAnd, DomainMatchStrategy: option.DomainMatchStrategy(C.DomainMatchStrategyFQDNOnly),
			Rules: []option.Rule{{Type: C.RuleTypeLogical, LogicalOptions: option.LogicalRule{RawLogicalRule: option.RawLogicalRule{
				Mode: C.LogicalTypeAnd, Rules: []option.Rule{{Type: C.RuleTypeDefault, DefaultOptions: option.DefaultRule{RawDefaultRule: option.RawDefaultRule{
					Domain: []string{domain}, DomainMatchStrategy: childStrategy,
				}}}},
			}}}},
		}})
		require.NoError(t, err)
		require.True(t, rule.Match(&metadata))
		headless, err := NewLogicalHeadlessRule(context.Background(), option.LogicalHeadlessRule{
			Mode: C.LogicalTypeAnd, DomainMatchStrategy: option.DomainMatchStrategy(C.DomainMatchStrategyFQDNOnly),
			Rules: []option.HeadlessRule{{Type: C.RuleTypeLogical, LogicalOptions: option.LogicalHeadlessRule{
				Mode: C.LogicalTypeAnd, Rules: []option.HeadlessRule{{Type: C.RuleTypeDefault, DefaultOptions: option.DefaultHeadlessRule{
					Domain: []string{domain}, DomainMatchStrategy: childStrategy,
				}}},
			}}},
		})
		require.NoError(t, err)
		metadata.ResetRuleCache()
		require.True(t, headless.Match(&metadata))
	}
}
