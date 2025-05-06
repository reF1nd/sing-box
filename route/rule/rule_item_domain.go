package rule

import (
	"strings"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/domain"
	E "github.com/sagernet/sing/common/exceptions"
)

var _ RuleItem = (*DomainItem)(nil)

type DomainItem struct {
	matcher             *domain.Matcher
	description         string
	domainMatchStrategy C.DomainMatchStrategy
}

func NewDomainItem(domains []string, domainSuffixes []string, domainMatchStrategy C.DomainMatchStrategy) (*DomainItem, error) {
	for _, domainItem := range domains {
		if domainItem == "" {
			return nil, E.New("domain: empty item is not allowed")
		}
	}
	for _, domainSuffixItem := range domainSuffixes {
		if domainSuffixItem == "" {
			return nil, E.New("domain_suffix: empty item is not allowed")
		}
	}
	var description string
	if dLen := len(domains); dLen > 0 {
		if dLen == 1 {
			description = "domain=" + domains[0]
		} else if dLen > 3 {
			description = "domain=[" + strings.Join(domains[:3], " ") + "...]"
		} else {
			description = "domain=[" + strings.Join(domains, " ") + "]"
		}
	}
	if dsLen := len(domainSuffixes); dsLen > 0 {
		if len(description) > 0 {
			description += " "
		}
		if dsLen == 1 {
			description += "domain_suffix=" + domainSuffixes[0]
		} else if dsLen > 3 {
			description += "domain_suffix=[" + strings.Join(domainSuffixes[:3], " ") + "...]"
		} else {
			description += "domain_suffix=[" + strings.Join(domainSuffixes, " ") + "]"
		}
	}
	return &DomainItem{
		domain.NewMatcher(domains, domainSuffixes, false),
		description,
		domainMatchStrategy,
	}, nil
}

func NewRawDomainItem(matcher *domain.Matcher, domainMatchStrategy C.DomainMatchStrategy) *DomainItem {
	return &DomainItem{
		matcher,
		"domain/domain_suffix=<binary>",
		domainMatchStrategy,
	}
}

func (r *DomainItem) Match(metadata *adapter.InboundContext) bool {
	var domainHost string
	switch r.domainMatchStrategy {
	case C.DomainMatchStrategyPreferFQDN:
		if metadata.Destination.IsFqdn() {
			domainHost = metadata.Destination.Fqdn
		} else if metadata.SniffHost != "" {
			domainHost = metadata.SniffHost
		} else {
			domainHost = metadata.Domain
		}
	case C.DomainMatchStrategyFQDNOnly:
		if metadata.Destination.IsFqdn() {
			domainHost = metadata.Destination.Fqdn
		}
	case C.DomainMatchStrategySniffHostOnly:
		if metadata.SniffHost != "" {
			domainHost = metadata.SniffHost
		}
	default:
		if metadata.SniffHost != "" {
			domainHost = metadata.SniffHost
		} else if metadata.Destination.IsFqdn() {
			domainHost = metadata.Destination.Fqdn
		} else {
			domainHost = metadata.Domain
		}
	}
	if domainHost == "" {
		return false
	}
	return r.matcher.Match(strings.ToLower(domainHost))
}

func (r *DomainItem) String() string {
	return r.description
}
