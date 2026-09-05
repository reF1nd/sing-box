package dns

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	R "github.com/sagernet/sing-box/route/rule"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

type discoveryTestTransport struct {
	fakeDNSTransport
}

func (t *discoveryTestTransport) Exchange(_ context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	t.queryCount.Add(1)
	response := new(mDNS.Msg)
	response.SetReply(message)
	response.RecursionAvailable = true
	response.Answer = []mDNS.RR{&mDNS.SVCB{
		Hdr:      mDNS.RR_Header{Name: message.Question[0].Name, Rrtype: mDNS.TypeSVCB, Class: mDNS.ClassINET, Ttl: 60},
		Priority: 1, Target: "resolver.example.",
	}}
	return response, nil
}

func (t *discoveryTestTransport) ExchangeAsync(ctx context.Context, message *mDNS.Msg, callback func(*mDNS.Msg, error)) {
	go func() { callback(t.Exchange(ctx, message)) }()
}

func TestResolverDiscoveryPolicy(t *testing.T) {
	t.Parallel()
	for _, config := range []struct {
		name, content string
		allow         bool
	}{
		{"default", `{}`, false},
		{"disabled", `{"allow_resolver_discovery":false}`, false},
		{"enabled", `{"allow_resolver_discovery":true}`, true},
	} {
		for _, mode := range []string{"direct", "rules", "legacy", "rules-reject", "legacy-reject"} {
			for _, async := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/async=%t", config.name, mode, async), func(t *testing.T) {
					t.Parallel()
					transport := &discoveryTestTransport{fakeDNSTransport: fakeDNSTransport{tag: "upstream"}}
					ctx := service.ContextWith[adapter.DNSTransportManager](context.Background(), &fakeDNSTransportManager{defaultTransport: transport})
					var options option.DNSOptions
					require.NoError(t, json.UnmarshalContext(ctx, []byte(config.content), &options))
					options.DisableCache = true
					router, err := NewRouter(ctx, log.NewNOPFactory(), options)
					require.NoError(t, err)
					t.Cleanup(func() { require.NoError(t, router.Close()) })
					router.legacyDNSMode = mode == "legacy" || mode == "legacy-reject"
					reject := mode == "rules-reject" || mode == "legacy-reject"
					var rejectRule *legacyAliasRule
					if reject {
						rejectRule = &legacyAliasRule{action: &R.RuleActionReject{Method: C.RuleActionRejectMethodDefault, Rcode: mDNS.RcodeRefused}}
						router.rules = []adapter.DNSRule{rejectRule}
					}
					queryOptions := adapter.DNSQueryOptions{}
					if mode == "direct" {
						queryOptions.Transport = transport
					}
					message := new(mDNS.Msg)
					message.SetQuestion("_DnS.resolver.arpa.", mDNS.TypeSVCB)
					message.Id = 1234
					var response *mDNS.Msg
					if async {
						type result struct {
							response *mDNS.Msg
							err      error
						}
						completed := make(chan result, 1)
						router.ExchangeAsync(ctx, message, queryOptions, func(response *mDNS.Msg, err error) { completed <- result{response, err} })
						select {
						case received := <-completed:
							response, err = received.response, received.err
						case <-time.After(5 * time.Second):
							t.Fatal("asynchronous exchange did not complete")
						}
					} else {
						response, err = router.Exchange(ctx, message, queryOptions)
					}
					require.NoError(t, err)
					require.NotNil(t, response)
					require.Equal(t, message.Id, response.Id)
					require.Equal(t, message.Question, response.Question)
					require.True(t, response.Response)
					if !config.allow {
						require.Equal(t, mDNS.RcodeSuccess, response.Rcode)
						require.True(t, response.RecursionDesired)
						require.True(t, response.RecursionAvailable)
						require.Empty(t, response.Answer)
						require.Zero(t, transport.queryCount.Load())
						if rejectRule != nil {
							require.Zero(t, rejectRule.matchCount+rejectRule.legacyPreMatchCount)
						}
					} else if reject {
						require.Equal(t, mDNS.RcodeRefused, response.Rcode)
						require.Empty(t, response.Answer)
						require.Zero(t, transport.queryCount.Load())
						require.Positive(t, rejectRule.matchCount+rejectRule.legacyPreMatchCount)
					} else {
						require.Equal(t, mDNS.RcodeSuccess, response.Rcode)
						require.Len(t, response.Answer, 1)
						require.Equal(t, "resolver.example.", response.Answer[0].(*mDNS.SVCB).Target)
						require.EqualValues(t, 1, transport.queryCount.Load())
					}
				})
			}
		}
	}
}

func TestResolverDiscoveryQueryScope(t *testing.T) {
	t.Parallel()
	for _, testCase := range []struct {
		name     string
		qtype    uint16
		rejected bool
	}{
		{"_dns.resolver.arpa.", mDNS.TypeSVCB, true},
		{"_DNS.example.", mDNS.TypeSVCB, true},
		{"_dns.resolver.arpa.", mDNS.TypeA, false},
		{"_dns.resolver.arpa.", mDNS.TypeAAAA, false},
		{"_dns.resolver.arpa.", mDNS.TypeHTTPS, false},
		{"example.com.", mDNS.TypeSVCB, false},
		{"prefix._dns.example.", mDNS.TypeSVCB, false},
		{"_dns-other.example.", mDNS.TypeSVCB, false},
		{"_dns.", mDNS.TypeSVCB, false},
		{".", mDNS.TypeSVCB, false},
	} {
		t.Run(fmt.Sprintf("%s/%d", testCase.name, testCase.qtype), func(t *testing.T) {
			t.Parallel()
			router, err := NewRouter(context.Background(), log.NewNOPFactory(), option.DNSOptions{})
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, router.Close()) })
			message := new(mDNS.Msg)
			message.SetQuestion(testCase.name, testCase.qtype)
			exchangeCtx, earlyResponse, err := router.prepareExchange(context.Background(), message)
			require.NoError(t, err)
			if testCase.rejected {
				require.Nil(t, exchangeCtx)
				require.NotNil(t, earlyResponse)
			} else {
				require.NotNil(t, exchangeCtx)
				require.Nil(t, earlyResponse)
			}
		})
	}
}
