package dns

import (
	"net"
	"testing"

	"github.com/sagernet/sing-box/adapter"

	mDNS "github.com/miekg/dns"
)

func TestApplyResponseOptionsCacheTTL(t *testing.T) {
	rewriteTTL := uint32(300)
	testCases := []struct {
		name       string
		response   func() *mDNS.Msg
		minTTL     uint32
		maxTTL     uint32
		rewriteTTL *uint32
		expected   uint32
	}{
		{
			name:     "unset preserves TTL above one day",
			response: func() *mDNS.Msg { return responseWithTTL(172800) },
			expected: 172800,
		},
		{
			name:     "minimum raises short TTL",
			response: func() *mDNS.Msg { return responseWithTTL(30) },
			minTTL:   60,
			expected: 60,
		},
		{
			name:     "minimum without maximum preserves long TTL",
			response: func() *mDNS.Msg { return responseWithTTL(172800) },
			minTTL:   60,
			expected: 172800,
		},
		{
			name:     "maximum lowers long TTL",
			response: func() *mDNS.Msg { return responseWithTTL(172800) },
			maxTTL:   86400,
			expected: 86400,
		},
		{
			name:     "minimum raises zero TTL",
			response: func() *mDNS.Msg { return responseWithTTL(0) },
			minTTL:   60,
			expected: 60,
		},
		{
			name: "maximum applies to negative response TTL",
			response: func() *mDNS.Msg {
				return &mDNS.Msg{Ns: []mDNS.RR{&mDNS.SOA{
					Hdr: mDNS.RR_Header{
						Name:   "example.com.",
						Rrtype: mDNS.TypeSOA,
						Class:  mDNS.ClassINET,
						Ttl:    600,
					},
					Minttl: 300,
				}}}
			},
			maxTTL:   120,
			expected: 120,
		},
		{
			name:     "minimum wins when greater than maximum",
			response: func() *mDNS.Msg { return responseWithTTL(120) },
			minTTL:   300,
			maxTTL:   60,
			expected: 300,
		},
		{
			name:       "rewrite TTL overrides cache bounds",
			response:   func() *mDNS.Msg { return responseWithTTL(120) },
			minTTL:     60,
			maxTTL:     90,
			rewriteTTL: &rewriteTTL,
			expected:   300,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			client := NewClient(ClientOptions{
				DisableCache: true,
				MinCacheTTL:  testCase.minTTL,
				MaxCacheTTL:  testCase.maxTTL,
			})
			response := testCase.response()
			actual := client.applyResponseOptions(
				mDNS.Question{Name: "example.com.", Qtype: mDNS.TypeA, Qclass: mDNS.ClassINET},
				response,
				adapter.DNSQueryOptions{RewriteTTL: testCase.rewriteTTL},
			)
			if actual != testCase.expected {
				t.Fatalf("expected TTL %d, got %d", testCase.expected, actual)
			}
			for _, recordList := range [][]mDNS.RR{response.Answer, response.Ns, response.Extra} {
				for _, record := range recordList {
					if record.Header().Rrtype == mDNS.TypeOPT {
						continue
					}
					if record.Header().Ttl != testCase.expected {
						t.Fatalf("expected response record TTL %d, got %d", testCase.expected, record.Header().Ttl)
					}
				}
			}
		})
	}
}

func responseWithTTL(ttl uint32) *mDNS.Msg {
	return &mDNS.Msg{Answer: []mDNS.RR{&mDNS.A{
		Hdr: mDNS.RR_Header{
			Name:   "example.com.",
			Rrtype: mDNS.TypeA,
			Class:  mDNS.ClassINET,
			Ttl:    ttl,
		},
		A: net.IPv4(192, 0, 2, 1),
	}}}
}
