package option

import (
	"reflect"

	"github.com/sagernet/sing-box/schema"
	"github.com/sagernet/sing/common/json/badoption"
)

type RouteOptions struct {
	GeoIP                      *GeoIPOptions                     `json:"geoip,omitempty" schema:"omit"`
	Geosite                    *GeositeOptions                   `json:"geosite,omitempty" schema:"omit"`
	Rules                      []Rule                            `json:"rules,omitempty"`
	RuleSet                    []RuleSet                         `json:"rule_set,omitempty"`
	Final                      string                            `json:"final,omitempty" reference:"outbound"`
	FindProcess                bool                              `json:"find_process,omitempty"`
	FindNeighbor               bool                              `json:"find_neighbor,omitempty"`
	DHCPLeaseFiles             badoption.Listable[string]        `json:"dhcp_lease_files,omitempty"`
	AutoDetectInterface        bool                              `json:"auto_detect_interface,omitempty"`
	OverrideAndroidVPN         bool                              `json:"override_android_vpn,omitempty"`
	DefaultInterface           string                            `json:"default_interface,omitempty"`
	DefaultMark                FwMark                            `json:"default_mark,omitempty"`
	DefaultDomainResolver      *DomainResolveOptions             `json:"default_domain_resolver,omitempty"`
	DefaultNetworkStrategy     *NetworkStrategy                  `json:"default_network_strategy,omitempty"`
	DefaultNetworkType         badoption.Listable[InterfaceType] `json:"default_network_type,omitempty"`
	DefaultFallbackNetworkType badoption.Listable[InterfaceType] `json:"default_fallback_network_type,omitempty"`
	DefaultFallbackDelay       badoption.Duration                `json:"default_fallback_delay,omitempty"`
	DefaultHTTPClient          string                            `json:"default_http_client,omitempty"`
	DefaultDomainMatchStrategy DomainMatchStrategy               `json:"default_domain_match_strategy,omitempty"`
}

func (o RouteOptions) DescribeSchema(builder schema.Builder) (*schema.Node, error) {
	return builder.Define("RouteOptions", func() (*schema.Node, error) {
		node := schema.StrictObject()
		err := builder.FlattenStruct(node, reflect.TypeFor[RouteOptions]())
		if err != nil {
			return nil, err
		}
		node.Properties.Put("default_domain_match_strategy", schema.StringEnum("", "as_is", "prefer_fqdn", "prefer_sniffhost"))
		return node, nil
	})
}

type GeoIPOptions struct {
	Path           string `json:"path,omitempty"`
	DownloadURL    string `json:"download_url,omitempty"`
	DownloadDetour string `json:"download_detour,omitempty" reference:"outbound"`
}

type GeositeOptions struct {
	Path           string `json:"path,omitempty"`
	DownloadURL    string `json:"download_url,omitempty"`
	DownloadDetour string `json:"download_detour,omitempty" reference:"outbound"`
}
