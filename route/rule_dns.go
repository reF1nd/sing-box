package route

import (
	"strings"

	"github.com/gofrs/uuid/v5"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-dns"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
)

func NewDNSRule(router adapter.Router, logger log.ContextLogger, options option.DNSRule, checkServer bool) (adapter.DNSRule, error) {
	switch options.Type {
	case "", C.RuleTypeDefault:
		if !options.DefaultOptions.IsValid() {
			return nil, E.New("missing conditions")
		}
		if len(options.DefaultOptions.Server) == 0 && checkServer {
			return nil, E.New("missing server field")
		}
		return NewDefaultDNSRule(router, logger, options.DefaultOptions)
	case C.RuleTypeLogical:
		if !options.LogicalOptions.IsValid() {
			return nil, E.New("missing conditions")
		}
		if len(options.LogicalOptions.Server) == 0 && checkServer {
			return nil, E.New("missing server field")
		}
		return NewLogicalDNSRule(router, logger, options.LogicalOptions)
	default:
		return nil, E.New("unknown rule type: ", options.Type)
	}
}

var _ adapter.DNSRule = (*DefaultDNSRule)(nil)

type FallBackRule struct {
	items  []RuleItem
	invert bool
}

func (r *FallBackRule) Start() error {
	for _, item := range r.items {
		err := common.Start(item)
		if err != nil {
			return err
		}
	}
	return nil
}

type DefaultDNSRule struct {
	abstractDefaultRule
	router       adapter.Router
	fallBackRule FallBackRule
	disableCache bool
	rewriteTTL   *uint32
	servers      []string
}

func NewDefaultDNSRule(router adapter.Router, logger log.ContextLogger, options option.DefaultDNSRule) (*DefaultDNSRule, error) {
	id, _ := uuid.NewV4()
	rule := &DefaultDNSRule{
		abstractDefaultRule: abstractDefaultRule{
			abstractRule: abstractRule{
				uuid:   id.String(),
				invert: options.Invert,
			},
		},
		router: router,
		fallBackRule: FallBackRule{
			invert: options.FallBackRule.Invert,
		},
		disableCache: options.DisableCache,
		rewriteTTL:   options.RewriteTTL,
		servers:      options.Server,
	}
	if len(options.Inbound) > 0 {
		item := NewInboundRule(options.Inbound)
		rule.items = append(rule.items, item)
		rule.allItems = append(rule.allItems, item)
	}
	if options.IPVersion > 0 {
		switch options.IPVersion {
		case 4, 6:
			item := NewIPVersionItem(options.IPVersion == 6)
			rule.items = append(rule.items, item)
			rule.allItems = append(rule.allItems, item)
		default:
			return nil, E.New("invalid ip version: ", options.IPVersion)
		}
	}
	if len(options.QueryType) > 0 {
		item := NewQueryTypeItem(options.QueryType)
		rule.items = append(rule.items, item)
		rule.allItems = append(rule.allItems, item)
	}
	if len(options.Network) > 0 {
		item := NewNetworkItem(options.Network)
		rule.items = append(rule.items, item)
		rule.allItems = append(rule.allItems, item)
	}
	if len(options.AuthUser) > 0 {
		item := NewAuthUserItem(options.AuthUser)
		rule.items = append(rule.items, item)
		rule.allItems = append(rule.allItems, item)
	}
	if len(options.Protocol) > 0 {
		item := NewProtocolItem(options.Protocol)
		rule.items = append(rule.items, item)
		rule.allItems = append(rule.allItems, item)
	}
	if len(options.Domain) > 0 || len(options.DomainSuffix) > 0 {
		item := NewDomainItem(options.Domain, options.DomainSuffix)
		rule.destinationAddressItems = append(rule.destinationAddressItems, item)
		rule.allItems = append(rule.allItems, item)
	}
	if len(options.DomainKeyword) > 0 {
		item := NewDomainKeywordItem(options.DomainKeyword)
		rule.destinationAddressItems = append(rule.destinationAddressItems, item)
		rule.allItems = append(rule.allItems, item)
	}
	if len(options.DomainRegex) > 0 {
		item, err := NewDomainRegexItem(options.DomainRegex)
		if err != nil {
			return nil, E.Cause(err, "domain_regex")
		}
		rule.destinationAddressItems = append(rule.destinationAddressItems, item)
		rule.allItems = append(rule.allItems, item)
	}
	if len(options.Geosite) > 0 {
		item := NewGeositeItem(router, logger, options.Geosite)
		rule.destinationAddressItems = append(rule.destinationAddressItems, item)
		rule.allItems = append(rule.allItems, item)
	}
	if len(options.SourceGeoIP) > 0 {
		item := NewGeoIPItem(router, logger, true, options.SourceGeoIP)
		rule.sourceAddressItems = append(rule.sourceAddressItems, item)
		rule.allItems = append(rule.allItems, item)
	}
	if len(options.SourceIPCIDR) > 0 {
		item, err := NewIPCIDRItem(true, options.SourceIPCIDR)
		if err != nil {
			return nil, E.Cause(err, "source_ip_cidr")
		}
		rule.sourceAddressItems = append(rule.sourceAddressItems, item)
		rule.allItems = append(rule.allItems, item)
	}
	if options.SourceIPIsPrivate {
		item := NewIPIsPrivateItem(true)
		rule.sourceAddressItems = append(rule.sourceAddressItems, item)
		rule.allItems = append(rule.allItems, item)
	}
	if len(options.SourcePort) > 0 {
		item := NewPortItem(true, options.SourcePort)
		rule.sourcePortItems = append(rule.sourcePortItems, item)
		rule.allItems = append(rule.allItems, item)
	}
	if len(options.SourcePortRange) > 0 {
		item, err := NewPortRangeItem(true, options.SourcePortRange)
		if err != nil {
			return nil, E.Cause(err, "source_port_range")
		}
		rule.sourcePortItems = append(rule.sourcePortItems, item)
		rule.allItems = append(rule.allItems, item)
	}
	if len(options.Port) > 0 {
		item := NewPortItem(false, options.Port)
		rule.destinationPortItems = append(rule.destinationPortItems, item)
		rule.allItems = append(rule.allItems, item)
	}
	if len(options.PortRange) > 0 {
		item, err := NewPortRangeItem(false, options.PortRange)
		if err != nil {
			return nil, E.Cause(err, "port_range")
		}
		rule.destinationPortItems = append(rule.destinationPortItems, item)
		rule.allItems = append(rule.allItems, item)
	}
	if len(options.ProcessName) > 0 {
		item := NewProcessItem(options.ProcessName)
		rule.items = append(rule.items, item)
		rule.allItems = append(rule.allItems, item)
	}
	if len(options.ProcessPath) > 0 {
		item := NewProcessPathItem(options.ProcessPath)
		rule.items = append(rule.items, item)
		rule.allItems = append(rule.allItems, item)
	}
	if len(options.PackageName) > 0 {
		item := NewPackageNameItem(options.PackageName)
		rule.items = append(rule.items, item)
		rule.allItems = append(rule.allItems, item)
	}
	if len(options.User) > 0 {
		item := NewUserItem(options.User)
		rule.items = append(rule.items, item)
		rule.allItems = append(rule.allItems, item)
	}
	if len(options.UserID) > 0 {
		item := NewUserIDItem(options.UserID)
		rule.items = append(rule.items, item)
		rule.allItems = append(rule.allItems, item)
	}
	if len(options.Outbound) > 0 {
		item := NewOutboundRule(options.Outbound)
		rule.items = append(rule.items, item)
		rule.allItems = append(rule.allItems, item)
	}
	if options.ClashMode != "" {
		item := NewClashModeItem(router, options.ClashMode)
		rule.items = append(rule.items, item)
		rule.allItems = append(rule.allItems, item)
	}
	if len(options.WIFISSID) > 0 {
		item := NewWIFISSIDItem(router, options.WIFISSID)
		rule.items = append(rule.items, item)
		rule.allItems = append(rule.allItems, item)
	}
	if len(options.WIFIBSSID) > 0 {
		item := NewWIFIBSSIDItem(router, options.WIFIBSSID)
		rule.items = append(rule.items, item)
		rule.allItems = append(rule.allItems, item)
	}
	if len(options.RuleSet) > 0 {
		item := NewRuleSetItem(router, options.RuleSet, false)
		rule.items = append(rule.items, item)
		rule.ruleSetItems = append(rule.ruleSetItems, item)
		rule.allItems = append(rule.allItems, item)
	}
	if len(options.FallBackRule.IPCIDR) > 0 {
		item, err := NewIPCIDRItem(false, options.FallBackRule.IPCIDR)
		if err != nil {
			return nil, E.Cause(err, "ipcidr")
		}
		rule.fallBackRule.items = append(rule.items, item)
	}
	if options.FallBackRule.IPIsPrivate {
		item := NewIPIsPrivateItem(false)
		rule.fallBackRule.items = append(rule.fallBackRule.items, item)
	}
	if len(options.FallBackRule.GeoIP) > 0 {
		item := NewGeoIPItem(router, logger, false, options.FallBackRule.GeoIP)
		rule.fallBackRule.items = append(rule.fallBackRule.items, item)
	}
	if len(options.FallBackRule.RuleSet) > 0 {
		item := NewRuleSetItem(router, options.FallBackRule.RuleSet, false)
		rule.fallBackRule.items = append(rule.items, item)
	}
	return rule, nil
}

func (r *DefaultDNSRule) DisableCache() bool {
	return r.disableCache
}

func (r *DefaultDNSRule) RewriteTTL() *uint32 {
	return r.rewriteTTL
}

func (r *DefaultDNSRule) String() string {
	var result string
	func() {
		if len(r.allItems) == 0 {
			result = "match_all"
			return
		}
		result = strings.Join(F.MapToString(r.allItems), " ")
		if r.invert {
			result = "!(" + result + ")"
		}
	}()
	func() {
		if len(r.fallBackRule.items) == 0 {
			return
		}
		fallback := "[" + strings.Join(F.MapToString(r.fallBackRule.items), " ") + "]"
		if r.fallBackRule.invert {
			fallback = "!" + fallback + ""
		}
		result = result + " fallback_rule=" + fallback + ""
	}()
	return result
}

func (r *DefaultDNSRule) Servers() []string {
	return r.servers
}

func (r *DefaultDNSRule) Start() error {
	for _, item := range r.allItems {
		err := common.Start(item)
		if err != nil {
			return err
		}
	}
	for _, server := range r.servers {
		transport, loaded := r.router.Transport(server)
		if !loaded {
			return E.New("server not found: ", server)
		}
		if _, isFakeIP := transport.(adapter.FakeIPTransport); isFakeIP && len(r.servers) > 1 {
			return E.New("fakeip can only be used stand-alone")
		}
		if _, isRCode := transport.(*dns.RCodeTransport); isRCode && len(r.servers) > 1 {
			return E.New("rcode server can only be used stand-alone")
		}
	}
	return r.fallBackRule.Start()
}

func (r *DefaultDNSRule) MatchFallback(metadata *adapter.InboundContext) bool {
	fallbackItem := r.fallBackRule.items
	if len(fallbackItem) == 0 {
		return false
	}
	for _, item := range fallbackItem {
		if item.Match(metadata) {
			return !r.fallBackRule.invert
		}
	}
	return r.fallBackRule.invert
}

var _ adapter.DNSRule = (*LogicalDNSRule)(nil)

type LogicalDNSRule struct {
	abstractLogicalRule
	router       adapter.Router
	fallBackRule FallBackRule
	disableCache bool
	rewriteTTL   *uint32
	servers      []string
}

func NewLogicalDNSRule(router adapter.Router, logger log.ContextLogger, options option.LogicalDNSRule) (*LogicalDNSRule, error) {
	id, _ := uuid.NewV4()
	r := &LogicalDNSRule{
		abstractLogicalRule: abstractLogicalRule{
			abstractRule: abstractRule{
				uuid:   id.String(),
				invert: options.Invert,
			},
			rules: make([]adapter.HeadlessRule, len(options.Rules)),
		},
		router: router,
		fallBackRule: FallBackRule{
			invert: options.FallBackRule.Invert,
		},
		disableCache: options.DisableCache,
		rewriteTTL:   options.RewriteTTL,
		servers:      options.Server,
	}
	switch options.Mode {
	case C.LogicalTypeAnd:
		r.mode = C.LogicalTypeAnd
	case C.LogicalTypeOr:
		r.mode = C.LogicalTypeOr
	default:
		return nil, E.New("unknown logical mode: ", options.Mode)
	}
	for i, subRule := range options.Rules {
		rule, err := NewDNSRule(router, logger, subRule, false)
		if err != nil {
			return nil, E.Cause(err, "sub rule[", i, "]")
		}
		r.rules[i] = rule
	}
	return r, nil
}

func (r *LogicalDNSRule) DisableCache() bool {
	return r.disableCache
}

func (r *LogicalDNSRule) RewriteTTL() *uint32 {
	return r.rewriteTTL
}

func (r *LogicalDNSRule) String() string {
	var result string
	var op string
	switch r.mode {
	case C.LogicalTypeAnd:
		op = "&&"
	case C.LogicalTypeOr:
		op = "||"
	}
	func() {
		if len(r.rules) == 0 {
			result = "match_all"
			return
		}
		result = strings.Join(F.MapToString(r.rules), " "+op+" ")
		if r.invert {
			result = "!(" + result + ")"
		}
	}()
	func() {
		if len(r.fallBackRule.items) == 0 {
			return
		}
		fallback := "[" + strings.Join(F.MapToString(r.fallBackRule.items), " ") + "]"
		if r.fallBackRule.invert {
			fallback = "!" + fallback + ""
		}
		result = result + " fallback_rule=" + fallback + ""
	}()
	return result
}

func (r *LogicalDNSRule) Servers() []string {
	return r.servers
}

func (r *LogicalDNSRule) Start() error {
	for _, rule := range common.FilterIsInstance(r.rules, func(it adapter.HeadlessRule) (common.Starter, bool) {
		rule, loaded := it.(common.Starter)
		return rule, loaded
	}) {
		err := rule.Start()
		if err != nil {
			return err
		}
	}
	for _, server := range r.servers {
		transport, loaded := r.router.Transport(server)
		if !loaded {
			return E.New("server not found: ", server)
		}
		if _, isFakeIP := transport.(adapter.FakeIPTransport); isFakeIP && len(r.servers) > 1 {
			return E.New("fakeip can only be used stand-alone")
		}
		if _, isRCode := transport.(*dns.RCodeTransport); isRCode && len(r.servers) > 1 {
			return E.New("rcode server can only be used stand-alone")
		}
	}
	return r.fallBackRule.Start()
}

func (r *LogicalDNSRule) MatchFallback(metadata *adapter.InboundContext) bool {
	fallbackItem := r.fallBackRule.items
	if len(fallbackItem) == 0 {
		return false
	}
	for _, item := range fallbackItem {
		if item.Match(metadata) {
			return !r.fallBackRule.invert
		}
	}
	return r.fallBackRule.invert
}
