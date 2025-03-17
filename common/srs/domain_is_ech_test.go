package srs

import (
	"bytes"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"

	"github.com/stretchr/testify/require"
)

func TestBinaryRejectsDomainIsECH(t *testing.T) {
	rules := option.PlainRuleSet{Rules: []option.HeadlessRule{{
		Type: C.RuleTypeLogical,
		LogicalOptions: option.LogicalHeadlessRule{Mode: C.LogicalTypeAnd, Rules: []option.HeadlessRule{{
			Type: C.RuleTypeDefault, DefaultOptions: option.DefaultHeadlessRule{DomainIsECH: true},
		}}},
	}}}
	var output bytes.Buffer
	require.ErrorContains(t, Write(&output, rules, C.RuleSetVersionCurrent), "domain_is_ech")
}
