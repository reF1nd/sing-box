package option

import (
	"net/netip"

	"github.com/sagernet/sing/common/json/badoption"
)

type EBPFInboundOptions struct {
	ListenOptions
	CgroupPath      string                           `json:"cgroup_path,omitempty"`
	Network         NetworkList                      `json:"network,omitempty"`
	DNSMode         string                           `json:"dns_mode,omitempty" enum:"hijack,off"`
	RedirectAddress badoption.Listable[netip.Prefix] `json:"redirect_address,omitempty" examples:"127.128.0.0/9,fd53:696e:672d:626f::/64"`
	BypassRuleSet   badoption.Listable[string]       `json:"bypass_rule_set,omitempty" reference:"rule_set"`
	IncludeUID      badoption.Listable[uint32]       `json:"include_uid,omitempty"`
	IncludeUIDRange badoption.Listable[string]       `json:"include_uid_range,omitempty"`
	ExcludeUID      badoption.Listable[uint32]       `json:"exclude_uid,omitempty"`
	ExcludeUIDRange badoption.Listable[string]       `json:"exclude_uid_range,omitempty"`
	SharedNetwork   EBPFSharedNetworkOptions         `json:"shared_network,omitempty"`
}

type EBPFSharedNetworkOptions struct {
	Enabled          bool                       `json:"enabled,omitempty"`
	IncludeInterface badoption.Listable[string] `json:"include_interface,omitempty"`
}
