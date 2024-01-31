package outboundprovider

import (
	"context"
	"encoding/json"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
)

var _ action = (*actionFilter)(nil)

func init() {
	registerAction("filter", func() action {
		return &actionFilter{}
	})
}

type actionFilterOptions struct {
	Rules   option.Listable[string] `json:"rules"`
	Logical string                  `json:"logical,omitempty"`
	Invert  bool                    `json:"invert,omitempty"`
}

type actionFilter struct {
	outboundMatcherGroup adapter.OutboundMatcher
	invert               bool
}

func (a *actionFilter) UnmarshalJSON(content []byte) error {
	var options actionFilterOptions
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
	return nil
}

func (a *actionFilter) apply(_ context.Context, _ adapter.Router, logger log.ContextLogger, processor *processor) error {
	var deleteOutbounds []string
	processor.ForeachOutbounds(func(outbound *option.Outbound) bool {
		if a.outboundMatcherGroup.MatchOptions(outbound) {
			if !a.invert {
				deleteOutbounds = append(deleteOutbounds, outbound.Tag)
			}
		} else {
			if a.invert {
				deleteOutbounds = append(deleteOutbounds, outbound.Tag)
			}
		}
		return true
	})
	if len(deleteOutbounds) == 0 {
		return nil
	}
	for _, tag := range deleteOutbounds {
		logger.Debug("filter outbound: ", tag)
		processor.DeleteOutbound(tag)
	}
	return nil
}
