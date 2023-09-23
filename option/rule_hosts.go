package option

import (
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
)

type _HostsRule struct {
	DefaultOptions DefaultHostsRule `json:"-"`
}

type HostsRule _HostsRule

type DefaultHostsRule struct {
	Domain        Listable[string] `json:"domain,omitempty"`
	DomainSuffix  Listable[string] `json:"domain_suffix,omitempty"`
	DomainKeyword Listable[string] `json:"domain_keyword,omitempty"`
	DomainRegex   Listable[string] `json:"domain_regex,omitempty"`
	Geosite       Listable[string] `json:"geosite,omitempty"`
	RuleSet       Listable[string] `json:"rule_set,omitempty"`
	IP            []*ListenAddress `json:"ip"`
}

func (r HostsRule) MarshalJSON() ([]byte, error) {
	v := r.DefaultOptions
	return MarshallObjects((_HostsRule)(r), v)
}

func (r *HostsRule) UnmarshalJSON(bytes []byte) error {
	err := json.Unmarshal(bytes, (*_HostsRule)(r))
	if err != nil {
		return err
	}
	v := &r.DefaultOptions
	err = UnmarshallExcluded(bytes, (*_HostsRule)(r), v)
	if err != nil {
		return E.Cause(err, "hosts rule")
	}
	return nil
}
