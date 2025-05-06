package rule

import (
	"strings"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
)

var _ RuleItem = (*DomainKeywordItem)(nil)

type DomainKeywordItem struct {
	keywords            []string
	domainMatchStrategy C.DomainMatchStrategy
}

func NewDomainKeywordItem(keywords []string, domainMatchStrategy C.DomainMatchStrategy) *DomainKeywordItem {
	return &DomainKeywordItem{keywords, domainMatchStrategy}
}

func (r *DomainKeywordItem) Match(metadata *adapter.InboundContext) bool {
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
	domainHost = strings.ToLower(domainHost)
	for _, keyword := range r.keywords {
		if strings.Contains(domainHost, keyword) {
			return true
		}
	}
	return false
}

func (r *DomainKeywordItem) String() string {
	kLen := len(r.keywords)
	if kLen == 1 {
		return "domain_keyword=" + r.keywords[0]
	} else if kLen > 3 {
		return "domain_keyword=[" + strings.Join(r.keywords[:3], " ") + "...]"
	} else {
		return "domain_keyword=[" + strings.Join(r.keywords, " ") + "]"
	}
}
