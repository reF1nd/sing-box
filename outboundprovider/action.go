package outboundprovider

import (
	"context"
	"encoding/json"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

type action interface {
	json.Unmarshaler
	apply(ctx context.Context, router adapter.Router, logger log.ContextLogger, processor *processor) error
}

type actionNewFn func() action

var actionMap map[string]actionNewFn

func registerAction(_type string, fn actionNewFn) {
	if actionMap == nil {
		actionMap = make(map[string]actionNewFn)
	}
	actionMap[_type] = fn
}

func newAction(options option.OutboundProviderActionOptions) (action, error) {
	fn, loaded := actionMap[options.Type]
	if !loaded {
		return nil, E.New("invalid action type: ", options.Type)
	}
	ac := fn()
	err := ac.UnmarshalJSON(options.RawMessage)
	if err != nil {
		return nil, err
	}
	return ac, nil
}
