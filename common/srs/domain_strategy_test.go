package srs

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"

	"github.com/stretchr/testify/require"
)

func TestBinaryRejectsUnsupportedDomainStrategy(t *testing.T) {
	defaultRule := option.HeadlessRule{
		Type: C.RuleTypeDefault,
		DefaultOptions: option.DefaultHeadlessRule{
			Domain: []string{"example.com"},
		},
	}
	customRule := defaultRule
	customRule.DefaultOptions.DomainMatchStrategy = option.DomainMatchStrategy(C.DomainMatchStrategyPreferSniffHost)
	for name, rule := range map[string]option.HeadlessRule{
		"default": customRule,
		"logical": {
			Type: C.RuleTypeLogical,
			LogicalOptions: option.LogicalHeadlessRule{
				Mode: C.LogicalTypeOr, Rules: []option.HeadlessRule{defaultRule},
				DomainMatchStrategy: option.DomainMatchStrategy(C.DomainMatchStrategyPreferSniffHost),
			},
		},
		"nested": {
			Type: C.RuleTypeLogical,
			LogicalOptions: option.LogicalHeadlessRule{
				Mode: C.LogicalTypeOr, Rules: []option.HeadlessRule{customRule},
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			ruleSet := option.PlainRuleSet{Rules: []option.HeadlessRule{rule}}
			var output bytes.Buffer
			require.ErrorContains(t, Write(&output, ruleSet, C.RuleSetVersionCurrent), "domain_match_strategy")
			file, err := os.Create(filepath.Join(t.TempDir(), "rule-set.mmap"))
			require.NoError(t, err)
			defer file.Close()
			require.ErrorContains(t, WriteMmap(file, option.PlainRuleSetCompat{
				Version: C.RuleSetVersionCurrent, Options: ruleSet,
			}), "domain_match_strategy")
		})
	}
	var output bytes.Buffer
	require.NoError(t, Write(&output, option.PlainRuleSet{Rules: []option.HeadlessRule{defaultRule}}, C.RuleSetVersionCurrent))
	_, err := Read(&output, true)
	require.NoError(t, err)
}
