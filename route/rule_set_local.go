package route

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
)

var _ adapter.RuleSet = (*LocalRuleSet)(nil)

type LocalRuleSet struct {
	abstractRuleSet
}

func NewLocalRuleSet(ctx context.Context, router adapter.Router, options option.RuleSet) (*LocalRuleSet, error) {
	ctx, cancel := context.WithCancel(ctx)
	ruleSet := LocalRuleSet{
		abstractRuleSet: abstractRuleSet{
			ctx:    ctx,
			cancel: cancel,
			tag:    options.Tag,
			pType:  "local",
			path:   options.Path,
			format: options.Format,
		},
	}
	return &ruleSet, ruleSet.loadFromFile(router, true)
}

func (s *LocalRuleSet) Update(router adapter.Router) error {
	return s.loadFromFile(router, false)
}

func (s *LocalRuleSet) StartContext(ctx context.Context, startContext adapter.RuleSetStartContext) error {
	return nil
}

func (s *LocalRuleSet) PostStart() error {
	return nil
}

func (s *LocalRuleSet) Close() error {
	s.cancel()
	return nil
}
