package option

import (
	"net/netip"

	"github.com/sagernet/sing-box/schema"
	"github.com/sagernet/sing/common/json/badoption"
)

type EBPFInboundOptions struct {
	Mode          string                     `json:"mode,omitempty" enum:"local,shared,hybrid"`
	Network       NetworkList                `json:"network,omitempty"`
	UDPTimeout    UDPTimeoutCompat           `json:"udp_timeout,omitempty"`
	DNSMode       string                     `json:"dns_mode,omitempty" enum:"hijack,respect_bypass,off"`
	BypassRuleSet badoption.Listable[string] `json:"bypass_rule_set,omitempty" reference:"rule_set"`
	Local         EBPFLocalOptions           `json:"local,omitempty"`
	Shared        EBPFSharedOptions          `json:"shared,omitempty"`
}

type EBPFLocalOptions struct {
	CgroupPath           string                     `json:"cgroup_path,omitempty"`
	IPv6Mode             string                     `json:"ipv6_mode,omitempty" enum:"auto,always,off"`
	BypassPrivateAddress *bool                      `json:"bypass_private_address,omitempty"`
	IncludeUID           badoption.Listable[uint32] `json:"include_uid,omitempty"`
	IncludeUIDRange      badoption.Listable[string] `json:"include_uid_range,omitempty"`
	ExcludeUID           badoption.Listable[uint32] `json:"exclude_uid,omitempty"`
	ExcludeUIDRange      badoption.Listable[string] `json:"exclude_uid_range,omitempty"`
	IncludeAndroidUser   badoption.Listable[int]    `json:"include_android_user,omitempty"`
	IncludePackage       badoption.Listable[string] `json:"include_package,omitempty"`
	ExcludePackage       badoption.Listable[string] `json:"exclude_package,omitempty"`
	StateCapacity        EBPFStateCapacity          `json:"state_capacity,omitempty"`
}

type EBPFSharedOptions struct {
	Interface            badoption.Listable[string]       `json:"interface,omitempty"`
	IPv6Mode             string                           `json:"ipv6_mode,omitempty" enum:"always,off"`
	BypassPrivateAddress *bool                            `json:"bypass_private_address,omitempty"`
	IncludeSourceCIDR    badoption.Listable[netip.Prefix] `json:"include_source_cidr,omitempty"`
	ExcludeSourceCIDR    badoption.Listable[netip.Prefix] `json:"exclude_source_cidr,omitempty"`
	IncludeMACAddress    badoption.Listable[string]       `json:"include_mac_address,omitempty"`
	ExcludeMACAddress    badoption.Listable[string]       `json:"exclude_mac_address,omitempty"`
	StateCapacity        EBPFStateCapacity                `json:"state_capacity,omitempty"`
	Advanced             EBPFSharedAdvancedOptions        `json:"advanced,omitempty"`
}

type EBPFSharedAdvancedOptions struct {
	TCPriority EBPFTCPriority `json:"tc_priority,omitempty"`
}

type EBPFStateCapacity uint32

type EBPFTCPriority uint16

func (EBPFStateCapacity) DescribeSchema(schema.Builder) (*schema.Node, error) {
	minimum := int64(0)
	maximum := uint64(1 << 20)
	return &schema.Node{
		Type:    "integer",
		Minimum: &minimum,
		Maximum: &maximum,
	}, nil
}

func (EBPFTCPriority) DescribeSchema(schema.Builder) (*schema.Node, error) {
	minimum := int64(1)
	maximum := uint64(1<<16 - 1)
	return &schema.Node{
		Type:    "integer",
		Minimum: &minimum,
		Maximum: &maximum,
	}, nil
}
