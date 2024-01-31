package outboundprovider

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

var _ action = (*actionTagFormat)(nil)

func init() {
	registerAction("tagformat", func() action {
		return &actionTagFormat{}
	})
}

type actionTagFormatOptions struct {
	Rules   option.Listable[string] `json:"rules"`
	Logical string                  `json:"logical,omitempty"`
	Invert  bool                    `json:"invert,omitempty"`
	Format  string                  `json:"format"`
}

type actionTagFormat struct {
	outboundMatcherGroup adapter.OutboundMatcher
	invert               bool
	format               string
}

func (a *actionTagFormat) UnmarshalJSON(content []byte) error {
	var options actionTagFormatOptions
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
	if options.Format == "" {
		return E.New("missing format")
	}
	a.format = options.Format
	return nil
}

func (a *actionTagFormat) formatTag(s string) string {
	if a.format == "" {
		return s
	}
	return fmt.Sprintf(a.format, s)
}

func (a *actionTagFormat) apply(_ context.Context, _ adapter.Router, logger log.ContextLogger, processor *processor) error {
	var outbounds []*option.Outbound
	processor.ForeachOutbounds(func(outbound *option.Outbound) bool {
		if a.outboundMatcherGroup.MatchOptions(outbound) {
			if !a.invert {
				outbounds = append(outbounds, outbound)
			}
		} else {
			if a.invert {
				outbounds = append(outbounds, outbound)
			}
		}
		return true
	})
	if len(outbounds) == 0 {
		return nil
	}
	outboundTagMap := make(map[string]string, len(outbounds)) // old -> new
	for _, outbound := range outbounds {
		formatTag := a.formatTag(outbound.Tag)
		logger.Debug("tagformat outbound: ", outbound.Tag, " -> ", formatTag)
		outboundTagMap[outbound.Tag] = formatTag
		outbound.Tag = formatTag
	}
	processor.ForeachGroupOutbounds(func(outbound *option.Outbound) bool {
		switch outbound.Type {
		case C.TypeSelector:
			for i, tag := range outbound.SelectorOptions.Outbounds {
				formatTag, loaded := outboundTagMap[tag]
				if loaded {
					outbound.SelectorOptions.Outbounds[i] = formatTag
				}
			}
			if outbound.SelectorOptions.Default != "" {
				formatTag, loaded := outboundTagMap[outbound.SelectorOptions.Default]
				if loaded {
					outbound.SelectorOptions.Default = formatTag
				}
			}
		case C.TypeURLTest:
			for i, tag := range outbound.URLTestOptions.Outbounds {
				formatTag, loaded := outboundTagMap[tag]
				if loaded {
					outbound.URLTestOptions.Outbounds[i] = formatTag
				}
			}
		}
		return true
	})
	return nil
}
