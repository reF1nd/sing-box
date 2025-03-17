package rule

import (
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"

	"github.com/stretchr/testify/require"
)

func TestDomainIsECH(t *testing.T) {
	const publicName = "public.example"
	defaultRule, err := NewDefaultRule(t.Context(), logger.NOP(), option.DefaultRule{
		RawDefaultRule: option.RawDefaultRule{Domain: []string{publicName}, DomainIsECH: true},
	})
	require.NoError(t, err)
	headlessRule, err := NewDefaultHeadlessRule(t.Context(), option.DefaultHeadlessRule{
		Domain: []string{publicName}, DomainIsECH: true,
	})
	require.NoError(t, err)
	andRule, err := NewDefaultRule(t.Context(), logger.NOP(), option.DefaultRule{
		RawDefaultRule: option.RawDefaultRule{Domain: []string{"other.example"}, DomainIsECH: true},
	})
	require.NoError(t, err)

	for _, testCase := range []struct {
		name         string
		protocol     string
		sniffHost    string
		publicName   string
		hasExtension bool
		matches      bool
	}{
		{name: "before sniff", publicName: publicName},
		{name: "TLS outer SNI", protocol: C.ProtocolTLS, sniffHost: publicName, publicName: "Public.Example", hasExtension: true, matches: true},
		{name: "QUIC outer SNI", protocol: C.ProtocolQUIC, sniffHost: publicName, publicName: publicName, hasExtension: true, matches: true},
		{name: "plain TLS to the same name", protocol: C.ProtocolTLS, sniffHost: publicName, publicName: publicName},
		{name: "no known public name", protocol: C.ProtocolTLS, sniffHost: publicName, hasExtension: true},
		{name: "different public name", protocol: C.ProtocolTLS, sniffHost: publicName, publicName: "other.example", hasExtension: true},
		{name: "HTTP", protocol: C.ProtocolHTTP, sniffHost: publicName, publicName: publicName, hasExtension: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			metadata := adapter.InboundContext{
				Protocol: testCase.protocol, SniffHost: testCase.sniffHost,
				ECHPublicName: testCase.publicName, SniffHasECHExtension: testCase.hasExtension,
			}
			require.Equal(t, testCase.matches, defaultRule.Match(&metadata))
			metadata.ResetRuleCache()
			require.Equal(t, testCase.matches, headlessRule.Match(&metadata))
			metadata.ResetRuleCache()
			require.False(t, andRule.Match(&metadata))
		})
	}
}
