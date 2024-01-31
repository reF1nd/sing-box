package adapter

import (
	"regexp"
	"strings"

	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

type OutboundMatcher interface {
	MatchOptions(outbound *option.Outbound) bool
	MatchOutbound(outbound Outbound) bool
}

type OutboundTagMatcher regexp.Regexp

func (m *OutboundTagMatcher) MatchOptions(outbound *option.Outbound) bool {
	return (*regexp.Regexp)(m).MatchString(outbound.Tag)
}

func (m *OutboundTagMatcher) MatchOutbound(outbound Outbound) bool {
	return (*regexp.Regexp)(m).MatchString(outbound.Tag())
}

type OutboundTypeMatcher string

func (m OutboundTypeMatcher) MatchOptions(outbound *option.Outbound) bool {
	return string(m) == outbound.Type
}

func (m OutboundTypeMatcher) MatchOutbound(outbound Outbound) bool {
	return string(m) == outbound.Type()
}

func NewOutboundMatcher(s string) (OutboundMatcher, error) {
	var ss string
	switch {
	case strings.HasPrefix(s, "type:"):
		ss = strings.TrimPrefix(s, "type:")
		return OutboundTypeMatcher(ss), nil
	case strings.HasPrefix(s, "tag:"):
		ss = strings.TrimPrefix(s, "tag:")
		regex, err := regexp.Compile(ss)
		if err != nil {
			return nil, E.Cause(err, "invalid rule: ", s)
		}
		return (*OutboundTagMatcher)(regex), nil
	default:
		ss = s
		regex, err := regexp.Compile(ss)
		if err != nil {
			return nil, E.Cause(err, "invalid rule: ", s)
		}
		return (*OutboundTagMatcher)(regex), nil
	}
}

type OutboundMatcherGroup struct {
	rules   []OutboundMatcher
	logical string // and / or
}

func NewOutboundMatcherGroup(rules []string, logical string) (OutboundMatcher, error) {
	switch logical {
	case "and":
	case "or":
	case "":
		return nil, E.New("missing logical")
	default:
		return nil, E.New("invalid logical: ", logical)
	}
	if len(rules) == 0 {
		return nil, E.New("missing rules")
	}
	g := &OutboundMatcherGroup{
		rules:   make([]OutboundMatcher, len(rules)),
		logical: logical,
	}
	for i, rule := range rules {
		matcher, err := NewOutboundMatcher(rule)
		if err != nil {
			return nil, E.Cause(err, "invalid rule[", i, "]: ", rule)
		}
		g.rules[i] = matcher
	}
	return g, nil
}

func (g *OutboundMatcherGroup) matchOptionsAnd(outbound *option.Outbound) bool {
	for _, rule := range g.rules {
		if !rule.MatchOptions(outbound) {
			return false
		}
	}
	return true
}

func (g *OutboundMatcherGroup) matchOptionsOr(outbound *option.Outbound) bool {
	for _, rule := range g.rules {
		if rule.MatchOptions(outbound) {
			return true
		}
	}
	return false
}

func (g *OutboundMatcherGroup) MatchOptions(outbound *option.Outbound) bool {
	switch g.logical {
	case "and":
		return g.matchOptionsAnd(outbound)
	case "or":
		return g.matchOptionsOr(outbound)
	}
	panic("unreachable")
}

func (g *OutboundMatcherGroup) matchOutboundAnd(outbound Outbound) bool {
	for _, rule := range g.rules {
		if !rule.MatchOutbound(outbound) {
			return false
		}
	}
	return true
}

func (g *OutboundMatcherGroup) matchOutboundOr(outbound Outbound) bool {
	for _, rule := range g.rules {
		if rule.MatchOutbound(outbound) {
			return true
		}
	}
	return false
}

func (g *OutboundMatcherGroup) MatchOutbound(outbound Outbound) bool {
	switch g.logical {
	case "and":
		return g.matchOutboundAnd(outbound)
	case "or":
		return g.matchOutboundOr(outbound)
	}
	panic("unreachable")
}
