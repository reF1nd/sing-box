package parser

import (
	"context"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badjson"
)

type _SingBoxDocument struct {
	Outbounds []option.Outbound `json:"outbounds"`
	Endpoints []option.Endpoint `json:"endpoints"`
}
type SingBoxDocument _SingBoxDocument

func (o *SingBoxDocument) UnmarshalJSONContext(ctx context.Context, inputContent []byte) error {
	var content badjson.JSONObject
	err := content.UnmarshalJSONContext(ctx, inputContent)
	if err != nil {
		return err
	}
	outbounds, hasOutbounds := content.Get("outbounds")
	if hasOutbounds {
		outboundList, valid := outbounds.(badjson.JSONArray)
		if !valid {
			return E.New("outbounds must be an array")
		}
		var outs badjson.JSONArray
		for i, outbound := range outboundList {
			object, valid := outbound.(*badjson.JSONObject)
			if !valid || object == nil {
				return E.New("outbound[", i, "] must be an object")
			}
			typeVal, loaded := object.Get("type")
			if !loaded {
				return E.New("missing type in outbound[", i, "]")
			}
			outboundType, valid := typeVal.(string)
			if !valid {
				return E.New("outbound[", i, "] type must be a string")
			}
			switch outboundType {
			case C.TypeDirect, C.TypeBlock, C.TypeDNS, C.TypeSelector, C.TypeURLTest:
				continue
			default:
				outs = append(outs, outbound)
			}
		}
		content.Put("outbounds", outs)
	}
	inputContent, err = content.MarshalJSONContext(ctx)
	if err != nil {
		return err
	}
	return json.UnmarshalContext(ctx, inputContent, (*_SingBoxDocument)(o))
}

func ParseBoxSubscription(ctx context.Context, content string) ([]option.Outbound, []option.Endpoint, error) {
	options, err := json.UnmarshalExtendedContext[SingBoxDocument](ctx, []byte(content))
	if err != nil {
		return nil, nil, err
	}
	if len(options.Outbounds) == 0 && len(options.Endpoints) == 0 {
		return nil, nil, E.New("no servers found")
	}
	return options.Outbounds, options.Endpoints, nil
}
