package rule

import (
	"regexp"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
)

var _ RuleItem = (*DomainRegexItem)(nil)

type DomainRegexItem struct {
	matchers            []*regexp.Regexp
	description         string
	domainMatchStrategy C.DomainMatchStrategy
}

func NewDomainRegexItem(expressions []string, domainMatchStrategy C.DomainMatchStrategy) (*DomainRegexItem, error) {
	matchers := make([]*regexp.Regexp, 0, len(expressions))
	for i, regex := range expressions {
		matcher, err := regexp.Compile(regex)
		if err != nil {
			return nil, E.Cause(err, "parse expression ", i)
		}
		matchers = append(matchers, matcher)
	}
	description := "domain_regex="
	eLen := len(expressions)
	if eLen == 1 {
		description += expressions[0]
	} else if eLen > 3 {
		description += F.ToString("[", strings.Join(expressions[:3], " "), "]")
	} else {
		description += F.ToString("[", strings.Join(expressions, " "), "]")
	}
	return &DomainRegexItem{matchers, description, domainMatchStrategy}, nil
}

func (r *DomainRegexItem) Match(metadata *adapter.InboundContext) bool {
	var domainHost string
	switch r.domainMatchStrategy {
	case C.DomainMatchStrategyPreferSniffHost:
		if metadata.SniffHost != "" {
			domainHost = metadata.SniffHost
		} else if metadata.Destination.IsFqdn() {
			domainHost = metadata.Destination.Fqdn
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
		if metadata.Destination.IsFqdn() {
			domainHost = metadata.Destination.Fqdn
		} else if metadata.SniffHost != "" {
			domainHost = metadata.SniffHost
		} else {
			domainHost = metadata.Domain
		}
	}
	if domainHost == "" {
		return false
	}
	domainHost = strings.ToLower(domainHost)
	for _, matcher := range r.matchers {
		if matcher.MatchString(domainHost) {
			return true
		}
	}
	return false
}

func (r *DomainRegexItem) String() string {
	return r.description
}
