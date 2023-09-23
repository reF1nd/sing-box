package route

import (
	"net/netip"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

var _ adapter.HostsRule = (*DefaultHostsRule)(nil)

type DefaultHostsRule struct {
	abstractDefaultRule
	ip []netip.Addr
}

func (r DefaultHostsRule) IP() []netip.Addr {
	return r.ip
}

func NewHostsRule(router adapter.Router, logger log.ContextLogger, options option.HostsRule) (adapter.HostsRule, error) {
	return NewDefaultHostsRule(router, logger, options.DefaultOptions)
}

func NewDefaultHostsRule(router adapter.Router, logger log.ContextLogger, options option.DefaultHostsRule) (*DefaultHostsRule, error) {
	rule := &DefaultHostsRule{
		abstractDefaultRule: abstractDefaultRule{},
	}
	if len(options.Domain) > 0 || len(options.DomainSuffix) > 0 {
		item := NewDomainItem(options.Domain, options.DomainSuffix)
		rule.destinationAddressItems = append(rule.destinationAddressItems, item)
		rule.allItems = append(rule.allItems, item)
	}
	if len(options.DomainKeyword) > 0 {
		item := NewDomainKeywordItem(options.DomainKeyword)
		rule.destinationAddressItems = append(rule.destinationAddressItems, item)
		rule.allItems = append(rule.allItems, item)
	}
	if len(options.DomainRegex) > 0 {
		item, err := NewDomainRegexItem(options.DomainRegex)
		if err != nil {
			return nil, E.Cause(err, "domain_regex")
		}
		rule.destinationAddressItems = append(rule.destinationAddressItems, item)
		rule.allItems = append(rule.allItems, item)
	}
	if len(options.Geosite) > 0 {
		item := NewGeositeItem(router, logger, options.Geosite)
		rule.destinationAddressItems = append(rule.destinationAddressItems, item)
		rule.allItems = append(rule.allItems, item)
	}
	if len(options.RuleSet) > 0 {
		item := NewRuleSetItem(router, options.RuleSet, false, false)
		rule.items = append(rule.items, item)
		rule.allItems = append(rule.allItems, item)
	}
	if len(options.IP) > 0 {
		for _, ip := range options.IP {
			rule.ip = append(rule.ip, ip.Build())
		}
	}
	return rule, nil
}
