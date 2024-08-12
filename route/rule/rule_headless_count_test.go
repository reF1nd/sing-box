package rule

import (
	"bytes"
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/srs"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badjson"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

type ruleCountTestNetworkManager struct {
	adapter.NetworkManager
}

func (m *ruleCountTestNetworkManager) InterfaceMonitor() tun.DefaultInterfaceMonitor {
	return nil
}

func newRuleCountTestRuleSet(t *testing.T, format string) *abstractRuleSet {
	t.Helper()
	return &abstractRuleSet{
		ctx:    service.ContextWith[adapter.NetworkManager](t.Context(), &ruleCountTestNetworkManager{}),
		logger: logger.NOP(),
		tag:    "test",
		format: format,
	}
}

func encodeRuleCountTestBinary(t *testing.T, version uint8, rules ...option.HeadlessRule) []byte {
	t.Helper()
	var buffer bytes.Buffer
	require.NoError(t, srs.Write(&buffer, option.PlainRuleSet{Rules: rules}, version))
	return buffer.Bytes()
}

func loadRuleCountTestSource(t *testing.T, rules ...option.HeadlessRule) *abstractRuleSet {
	t.Helper()
	content, err := json.Marshal(option.PlainRuleSetCompat{
		Version: C.RuleSetVersionCurrent,
		Options: option.PlainRuleSet{Rules: rules},
	})
	require.NoError(t, err)
	ruleSet := newRuleCountTestRuleSet(t, C.RuleSetFormatSource)
	require.NoError(t, ruleSet.loadBytes(content, nil))
	return ruleSet
}

func loadRuleCountTestBinary(t *testing.T, version uint8, rules ...option.HeadlessRule) *abstractRuleSet {
	t.Helper()
	ruleSet := newRuleCountTestRuleSet(t, C.RuleSetFormatBinary)
	require.NoError(t, ruleSet.loadBytes(encodeRuleCountTestBinary(t, version, rules...), nil))
	return ruleSet
}

func ruleCountTestRule(options option.DefaultHeadlessRule) option.HeadlessRule {
	return option.HeadlessRule{Type: C.RuleTypeDefault, DefaultOptions: options}
}

func ruleCountTestPrefixes(prefixes ...string) badoption.Listable[*badoption.Prefixable] {
	return common.Map(prefixes, func(it string) *badoption.Prefixable {
		return common.Ptr(badoption.Prefixable(netip.MustParsePrefix(it)))
	})
}

func TestRuleSetRuleCount(t *testing.T) {
	t.Parallel()

	interfaceAddress := new(badjson.TypedMap[option.InterfaceType, badoption.Listable[*badoption.Prefixable]])
	interfaceAddress.Put(option.InterfaceType(C.InterfaceTypeWIFI), ruleCountTestPrefixes("10.0.0.0/8", "172.16.0.0/12"))
	interfaceAddress.Put(option.InterfaceType(C.InterfaceTypeCellular), ruleCountTestPrefixes("192.168.0.0/16"))

	testCases := []struct {
		name  string
		count uint64
		rules []option.HeadlessRule
	}{
		{
			name:  "domain and domain_suffix",
			count: 5,
			rules: []option.HeadlessRule{ruleCountTestRule(option.DefaultHeadlessRule{
				Domain:       []string{"a.com", "b.com"},
				DomainSuffix: []string{"c.com", ".d.com", "e.com"},
			})},
		},
		{
			name:  "all destination address conditions",
			count: 8,
			rules: []option.HeadlessRule{ruleCountTestRule(option.DefaultHeadlessRule{
				Domain:        []string{"a.com"},
				DomainSuffix:  []string{"b.com", "c.com"},
				DomainKeyword: []string{"d", "e"},
				DomainRegex:   []string{"^f$"},
				IPCIDR:        []string{"1.0.0.0/24", "3.0.0.0/24"},
			})},
		},
		{
			name:  "ip_cidr",
			count: 4,
			rules: []option.HeadlessRule{ruleCountTestRule(option.DefaultHeadlessRule{
				IPCIDR: []string{"1.0.0.0/24", "3.0.0.0/24", "5.0.0.0/24", "2001:db8::/32"},
			})},
		},
		{
			name:  "source_ip_cidr",
			count: 2,
			rules: []option.HeadlessRule{ruleCountTestRule(option.DefaultHeadlessRule{
				SourceIPCIDR: []string{"1.0.0.0/24", "2001:db8::/32"},
			})},
		},
		{
			name:  "port and port_range",
			count: 3,
			rules: []option.HeadlessRule{ruleCountTestRule(option.DefaultHeadlessRule{
				Port:      []uint16{80, 443},
				PortRange: []string{"1000:2000"},
			})},
		},
		{
			name:  "source_port and source_port_range",
			count: 3,
			rules: []option.HeadlessRule{ruleCountTestRule(option.DefaultHeadlessRule{
				SourcePort:      []uint16{80},
				SourcePortRange: []string{"1000:2000", "3000:4000"},
			})},
		},
		{
			name:  "query_type",
			count: 2,
			rules: []option.HeadlessRule{ruleCountTestRule(option.DefaultHeadlessRule{QueryType: []option.DNSQueryType{1, 28}})},
		},
		{
			name:  "network",
			count: 2,
			rules: []option.HeadlessRule{ruleCountTestRule(option.DefaultHeadlessRule{Network: []string{"tcp", "udp"}})},
		},
		{
			name:  "process_name",
			count: 3,
			rules: []option.HeadlessRule{ruleCountTestRule(option.DefaultHeadlessRule{ProcessName: []string{"a", "b", "c"}})},
		},
		{
			name:  "process_path",
			count: 2,
			rules: []option.HeadlessRule{ruleCountTestRule(option.DefaultHeadlessRule{ProcessPath: []string{"/a", "/b"}})},
		},
		{
			name:  "process_path_regex",
			count: 2,
			rules: []option.HeadlessRule{ruleCountTestRule(option.DefaultHeadlessRule{ProcessPathRegex: []string{"^/a$", "^/b$"}})},
		},
		{
			name:  "package_name",
			count: 2,
			rules: []option.HeadlessRule{ruleCountTestRule(option.DefaultHeadlessRule{PackageName: []string{"a.b", "c.d"}})},
		},
		{
			name:  "package_name_regex",
			count: 2,
			rules: []option.HeadlessRule{ruleCountTestRule(option.DefaultHeadlessRule{PackageNameRegex: []string{"^a$", "^b$"}})},
		},
		{
			name:  "network_type",
			count: 2,
			rules: []option.HeadlessRule{ruleCountTestRule(option.DefaultHeadlessRule{
				NetworkType: []option.InterfaceType{option.InterfaceType(C.InterfaceTypeWIFI), option.InterfaceType(C.InterfaceTypeCellular)},
			})},
		},
		{
			name:  "wifi_ssid",
			count: 2,
			rules: []option.HeadlessRule{ruleCountTestRule(option.DefaultHeadlessRule{WIFISSID: []string{"a", "b"}})},
		},
		{
			name:  "wifi_bssid",
			count: 2,
			rules: []option.HeadlessRule{ruleCountTestRule(option.DefaultHeadlessRule{WIFIBSSID: []string{"00:00:00:00:00:01", "00:00:00:00:00:02"}})},
		},
		{
			name:  "network_is_expensive",
			count: 1,
			rules: []option.HeadlessRule{ruleCountTestRule(option.DefaultHeadlessRule{NetworkIsExpensive: true})},
		},
		{
			name:  "network_is_constrained",
			count: 1,
			rules: []option.HeadlessRule{ruleCountTestRule(option.DefaultHeadlessRule{NetworkIsConstrained: true})},
		},
		{
			name:  "default_interface_address requires every value",
			count: 1,
			rules: []option.HeadlessRule{ruleCountTestRule(option.DefaultHeadlessRule{
				DefaultInterfaceAddress: ruleCountTestPrefixes("10.0.0.0/8", "172.16.0.0/12"),
			})},
		},
		{
			name:  "network_interface_address requires every interface type",
			count: 1,
			rules: []option.HeadlessRule{ruleCountTestRule(option.DefaultHeadlessRule{NetworkInterfaceAddress: interfaceAddress})},
		},
		{
			name:  "domain and port are one rule",
			count: 1,
			rules: []option.HeadlessRule{ruleCountTestRule(option.DefaultHeadlessRule{
				Domain: []string{"a.com", "b.com"},
				Port:   []uint16{443},
			})},
		},
		{
			name:  "process_name and network are one rule",
			count: 1,
			rules: []option.HeadlessRule{ruleCountTestRule(option.DefaultHeadlessRule{
				ProcessName: []string{"a", "b"},
				Network:     []string{"tcp"},
			})},
		},
		{
			name:  "logical rule is one rule",
			count: 1,
			rules: []option.HeadlessRule{{
				Type: C.RuleTypeLogical,
				LogicalOptions: option.LogicalHeadlessRule{
					Mode: C.LogicalTypeOr,
					Rules: []option.HeadlessRule{
						ruleCountTestRule(option.DefaultHeadlessRule{Domain: []string{"a.com", "b.com"}}),
						ruleCountTestRule(option.DefaultHeadlessRule{Port: []uint16{443}}),
					},
				},
			}},
		},
		{
			name:  "rules are summed",
			count: 6,
			rules: []option.HeadlessRule{
				ruleCountTestRule(option.DefaultHeadlessRule{Domain: []string{"a.com", "b.com"}}),
				ruleCountTestRule(option.DefaultHeadlessRule{IPCIDR: []string{"1.0.0.0/24", "3.0.0.0/24", "5.0.0.0/24"}}),
				ruleCountTestRule(option.DefaultHeadlessRule{Domain: []string{"c.com"}, Port: []uint16{443}}),
			},
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, testCase.count, loadRuleCountTestSource(t, testCase.rules...).RuleCount(), "source")
			require.Equal(t, testCase.count, loadRuleCountTestBinary(t, C.RuleSetVersionCurrent, testCase.rules...).RuleCount(), "binary")
		})
	}
}

func TestRuleSetRuleCountDomainMatcher(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name  string
		count uint64
		rule  option.DefaultHeadlessRule
	}{
		{
			name:  "undotted suffix",
			count: 2,
			rule:  option.DefaultHeadlessRule{DomainSuffix: []string{"a.com", "b.com"}},
		},
		{
			name:  "dotted suffix",
			count: 2,
			rule:  option.DefaultHeadlessRule{DomainSuffix: []string{".a.com", ".b.com"}},
		},
		{
			name:  "domain below undotted suffix",
			count: 2,
			rule: option.DefaultHeadlessRule{
				Domain:       []string{"sub.a.com"},
				DomainSuffix: []string{"a.com"},
			},
		},
		{
			name:  "mixed",
			count: 7,
			rule: option.DefaultHeadlessRule{
				Domain:       []string{"full-1.com", "full-2.com", "sub.undotted-1.com"},
				DomainSuffix: []string{"undotted-1.com", "undotted-2.com", ".dotted-1.com", ".dotted-2.com"},
			},
		},
		{
			name:  "domain and dotted suffix decode as one undotted suffix",
			count: 1,
			rule: option.DefaultHeadlessRule{
				Domain:       []string{"a.com"},
				DomainSuffix: []string{".a.com"},
			},
		},
	}
	versions := []uint8{C.RuleSetVersion1, C.RuleSetVersion2, C.RuleSetVersion3, C.RuleSetVersion4, C.RuleSetVersion5}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			for _, version := range versions {
				rule := ruleCountTestRule(testCase.rule)
				content := encodeRuleCountTestBinary(t, version, rule)
				compat, err := srs.Read(bytes.NewReader(content), false)
				require.NoError(t, err)
				matcher := compat.Options.Rules[0].DefaultOptions.DomainMatcher
				domains, suffixes := matcher.Dump()
				require.Len(t, append(domains, suffixes...), int(testCase.count), "version %d", version)
				require.Equal(t, testCase.count, countDomainMatcher(matcher), "version %d", version)
				require.Equal(t, testCase.count, loadRuleCountTestBinary(t, version, rule).RuleCount(), "version %d", version)
			}
		})
	}
}

func TestRuleSetRuleCountAdGuardDomain(t *testing.T) {
	t.Parallel()

	rule := ruleCountTestRule(option.DefaultHeadlessRule{
		AdGuardDomain: []string{"||a.com^", "|b.com^", "c.com", "||d.com^"},
	})
	require.Equal(t, uint64(4), loadRuleCountTestBinary(t, C.RuleSetVersionCurrent, rule).RuleCount())

	ruleSet := newRuleCountTestRuleSet(t, C.RuleSetFormatSource)
	require.NoError(t, ruleSet.reloadRules([]option.HeadlessRule{rule}, nil))
	require.Equal(t, uint64(4), ruleSet.RuleCount())
}

func TestRuleSetRuleCountBinaryIPPrefixes(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		count    uint64
		prefixes []string
	}{
		{"ipv4 adjacent prefixes need two prefixes", 2, []string{"10.0.1.0/24", "10.0.2.0/24"}},
		{"ipv6 adjacent prefixes need two prefixes", 2, []string{"2001:db8:1::/48", "2001:db8:2::/48"}},
		{"ipv4 adjacent prefixes merge into one", 1, []string{"10.0.0.0/24", "10.0.1.0/24"}},
		{"ipv6 adjacent prefixes merge into one", 1, []string{"2001:db8::/48", "2001:db8:1::/48"}},
		{"separate families", 3, []string{"10.0.0.0/24", "192.168.0.0/24", "2001:db8::/32"}},
		{"whole address space", 1, []string{"0.0.0.0/0"}},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, testCase.count, loadRuleCountTestBinary(t, C.RuleSetVersionCurrent,
				ruleCountTestRule(option.DefaultHeadlessRule{IPCIDR: testCase.prefixes})).RuleCount(), "ip_cidr")
			require.Equal(t, testCase.count, loadRuleCountTestBinary(t, C.RuleSetVersionCurrent,
				ruleCountTestRule(option.DefaultHeadlessRule{SourceIPCIDR: testCase.prefixes})).RuleCount(), "source_ip_cidr")
		})
	}
}

func TestRuleSetRuleCountReload(t *testing.T) {
	t.Parallel()

	ruleSet := loadRuleCountTestBinary(t, C.RuleSetVersionCurrent, ruleCountTestRule(option.DefaultHeadlessRule{
		Domain: []string{"a.com", "b.com", "c.com"},
	}))
	require.Equal(t, uint64(3), ruleSet.RuleCount())

	ruleSet.Cleanup()
	require.Nil(t, ruleSet.rules)
	require.Equal(t, uint64(3), ruleSet.RuleCount())

	require.NoError(t, ruleSet.loadBytes(encodeRuleCountTestBinary(t, C.RuleSetVersionCurrent, ruleCountTestRule(option.DefaultHeadlessRule{
		Domain: []string{"a.com"},
	})), nil))
	require.Equal(t, uint64(1), ruleSet.RuleCount())
}
