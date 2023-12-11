package route

import (
	"strings"

	"github.com/sagernet/sing-box/adapter"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
)

var _ RuleItem = (*RuleSetItem)(nil)

type RuleSetItem struct {
	router            adapter.Router
	tagList           []string
	setList           []adapter.HeadlessRule
	useIPRule         bool
	ipcidrMatchSource bool
}

func NewRuleSetItem(router adapter.Router, tagList []string, ipCIDRMatchSource bool) *RuleSetItem {
	return &RuleSetItem{
		router:            router,
		tagList:           tagList,
		ipcidrMatchSource: ipCIDRMatchSource,
	}
}

func (r *RuleSetItem) Start() error {
	for _, tag := range r.tagList {
		ruleSet, loaded := r.router.RuleSet(tag)
		if !loaded {
			return E.New("rule-set not found: ", tag)
		}
		r.setList = append(r.setList, ruleSet)
		if ruleSet.UseIPRule() {
			r.useIPRule = true
		}
	}
	return nil
}

func (r *RuleSetItem) Match(metadata *adapter.InboundContext) bool {
	metadata.IPCIDRMatchSource = r.ipcidrMatchSource
	for _, ruleSet := range r.setList {
		if ruleSet.Match(metadata) {
			return true
		}
	}
	return false
}

func (r *RuleSetItem) String() string {
	if len(r.tagList) == 1 {
		return F.ToString("rule_set=", r.tagList[0])
	} else {
		return F.ToString("rule_set=[", strings.Join(r.tagList, " "), "]")
	}
}
