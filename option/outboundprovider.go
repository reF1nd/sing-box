package option

import (
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
)

type OutboundProvider struct {
	Tag             string                                  `json:"tag"`
	URL             string                                  `json:"url"`
	CacheTag        string                                  `json:"cache_tag,omitempty"`
	UpdateInterval  Duration                                `json:"update_interval,omitempty"`
	RequestTimeout  Duration                                `json:"request_timeout,omitempty"`
	HTTP3           bool                                    `json:"http3,omitempty"`
	Headers         map[string]string                       `json:"headers,omitempty"`
	SelectorOptions SelectorOutboundOptions                 `json:"selector,omitempty"`
	Optimize        bool                                    `json:"optimize,omitempty"`
	Actions         Listable[OutboundProviderActionOptions] `json:"actions,omitempty"`
	DialerOptions
}

type _OutboundProviderActionOptions struct {
	Type       string          `json:"type"`
	RawMessage json.RawMessage `json:"-"`
}

type OutboundProviderActionOptions _OutboundProviderActionOptions

func (o *OutboundProviderActionOptions) UnmarshalJSON(content []byte) error {
	var m map[string]any
	err := json.Unmarshal(content, &m)
	if err != nil {
		return err
	}
	typeAny, loaded := m["type"]
	if !loaded {
		return E.New("missing type")
	}
	typeStr, loaded := typeAny.(string)
	if !loaded || typeStr == "" {
		return E.New("invalid type")
	}
	o.Type = typeStr
	delete(m, "type")
	raw, err := json.Marshal(m)
	if err != nil {
		return err
	}
	o.RawMessage = raw
	return nil
}

func (o *OutboundProviderActionOptions) MarshalJSON() ([]byte, error) {
	var m map[string]any
	err := json.Unmarshal(o.RawMessage, &m)
	if err != nil {
		return nil, err
	}
	m["type"] = o.Type
	return json.Marshal(m)
}
