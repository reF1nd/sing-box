package outboundprovider

import (
	"context"
	"encoding/json"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

var _ action = (*actionGroup)(nil)

func init() {
	registerAction("group", func() action {
		return &actionGroup{}
	})
}

type actionGroupOptions struct {
	Rules    option.Listable[string] `json:"rules,omitempty"`
	Logical  string                  `json:"logical,omitempty"`
	Invert   bool                    `json:"invert,omitempty"`
	Outbound option.Outbound         `json:"outbound"`
}

type actionGroup struct {
	outboundMatcherGroup adapter.OutboundMatcher
	invert               bool
	outbound             option.Outbound
}

func (a *actionGroup) UnmarshalJSON(content []byte) error {
	var options actionGroupOptions
	err := json.Unmarshal(content, &options)
	if err != nil {
		return err
	}
	logical := options.Logical
	if logical == "" {
		logical = "or"
	}
	a.outboundMatcherGroup, err = adapter.NewOutboundMatcherGroup(options.Rules, logical)
	if err != nil {
		return err
	}
	a.invert = options.Invert
	switch options.Outbound.Type {
	case C.TypeSelector:
	case C.TypeURLTest:
	default:
		return E.New("invalid outbound type: ", options.Outbound.Type)
	}
	a.outbound = options.Outbound
	return nil
}

func (a *actionGroup) apply(_ context.Context, _ adapter.Router, logger log.ContextLogger, processor *processor) error {
	var outbounds []string
	processor.ForeachOutbounds(func(outbound *option.Outbound) bool {
		if a.outboundMatcherGroup.MatchOptions(outbound) {
			if !a.invert {
				outbounds = append(outbounds, outbound.Tag)
			}
		} else {
			if a.invert {
				outbounds = append(outbounds, outbound.Tag)
			}
		}
		return true
	})
	if len(outbounds) == 0 {
		return E.New("no outbounds matched")
	}
	outbound := a.outbound
	switch outbound.Type {
	case C.TypeSelector:
		if len(outbound.SelectorOptions.Outbounds) > 0 {
			oldOutbounds := outbound.SelectorOptions.Outbounds
			outbound.SelectorOptions.Outbounds = make([]string, 0, len(oldOutbounds)+len(outbounds))
			outbound.SelectorOptions.Outbounds = append(outbound.SelectorOptions.Outbounds, oldOutbounds...)
			outbound.SelectorOptions.Outbounds = append(outbound.SelectorOptions.Outbounds, outbounds...)
		} else {
			outbound.SelectorOptions.Outbounds = outbounds
		}
	case C.TypeURLTest:
		if len(outbound.URLTestOptions.Outbounds) > 0 {
			oldOutbounds := outbound.URLTestOptions.Outbounds
			outbound.URLTestOptions.Outbounds = make([]string, 0, len(oldOutbounds)+len(outbounds))
			outbound.URLTestOptions.Outbounds = append(outbound.URLTestOptions.Outbounds, oldOutbounds...)
			outbound.URLTestOptions.Outbounds = append(outbound.URLTestOptions.Outbounds, outbounds...)
		} else {
			outbound.URLTestOptions.Outbounds = outbounds
		}
	}
	processor.AddGroupOutbound(outbound)
	logger.Debug("add group outbound: ", outbound.Tag)
	return nil
}
