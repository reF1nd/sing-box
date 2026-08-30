package option

import (
	"net/netip"

	"github.com/sagernet/sing-box/schema"
	"github.com/sagernet/sing/common/json/badoption"
)

type EBPFInboundOptions struct {
	Network       NetworkList                `json:"network,omitempty"`
	UDPTimeout    UDPTimeoutCompat           `json:"udp_timeout,omitempty"`
	TCPriority    EBPFTCPriority             `json:"tc_priority,omitempty"`
	BypassRuleSet badoption.Listable[string] `json:"bypass_rule_set,omitempty" reference:"rule_set"`
	Local         EBPFLocalOptions           `json:"local,omitempty"`
	Shared        EBPFSharedOptions          `json:"shared,omitempty"`
}

type EBPFLocalOptions struct {
	Enabled              *bool                      `json:"enabled,omitempty"`
	DNSMode              string                     `json:"dns_mode,omitempty" enum:"hijack,respect_policy,off"`
	DataPlane            string                     `json:"data_plane,omitempty" enum:"tc,cgroup"`
	CgroupPath           string                     `json:"cgroup_path,omitempty"`
	IPv6                 *bool                      `json:"ipv6,omitempty"`
	BypassPrivateAddress *bool                      `json:"bypass_private_address,omitempty"`
	IncludeUID           badoption.Listable[uint32] `json:"include_uid,omitempty"`
	IncludeUIDRange      badoption.Listable[string] `json:"include_uid_range,omitempty"`
	ExcludeUID           badoption.Listable[uint32] `json:"exclude_uid,omitempty"`
	ExcludeUIDRange      badoption.Listable[string] `json:"exclude_uid_range,omitempty"`
	IncludeAndroidUser   badoption.Listable[int]    `json:"include_android_user,omitempty"`
	IncludePackage       badoption.Listable[string] `json:"include_package,omitempty"`
	ExcludePackage       badoption.Listable[string] `json:"exclude_package,omitempty"`
	BypassPort           badoption.Listable[uint16] `json:"bypass_port,omitempty"`
	BypassPortRange      badoption.Listable[string] `json:"bypass_port_range,omitempty"`
}

type EBPFSharedOptions struct {
	Enabled              *bool                            `json:"enabled,omitempty"`
	DataPlane            string                           `json:"data_plane,omitempty" enum:"socket_assign,packet_rewrite"`
	DNSMode              string                           `json:"dns_mode,omitempty" enum:"hijack,respect_policy,off"`
	Interface            badoption.Listable[string]       `json:"interface,omitempty"`
	IPv6                 *bool                            `json:"ipv6,omitempty"`
	BypassPrivateAddress *bool                            `json:"bypass_private_address,omitempty"`
	IncludeSourceCIDR    badoption.Listable[netip.Prefix] `json:"include_source_cidr,omitempty"`
	ExcludeSourceCIDR    badoption.Listable[netip.Prefix] `json:"exclude_source_cidr,omitempty"`
	IncludeMACAddress    badoption.Listable[string]       `json:"include_mac_address,omitempty"`
	ExcludeMACAddress    badoption.Listable[string]       `json:"exclude_mac_address,omitempty"`
	BypassPort           badoption.Listable[uint16]       `json:"bypass_port,omitempty"`
	BypassPortRange      badoption.Listable[string]       `json:"bypass_port_range,omitempty"`
}

// EffectiveEnablement returns the local and shared paths selected by the
// current configuration. With no explicit enablement, local interception is
// enabled by default.
func (o EBPFInboundOptions) EffectiveEnablement() (local, shared bool) {
	if o.Local.Enabled != nil || o.Shared.Enabled != nil {
		return o.Local.Enabled != nil && *o.Local.Enabled, o.Shared.Enabled != nil && *o.Shared.Enabled
	}
	return true, false
}

type EBPFTCPriority uint16

func (EBPFTCPriority) DescribeSchema(schema.Builder) (*schema.Node, error) {
	minimum := int64(1)
	maximum := uint64(1<<16 - 1)
	return &schema.Node{
		Type:    "integer",
		Minimum: &minimum,
		Maximum: &maximum,
	}, nil
}
