package dns

import (
	"net"
	"testing"
	"time"

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

type stubPersistentDNSCache struct {
	adapter.DNSCacheStore
	raw      []byte
	expireAt time.Time
	present  bool
	deleted  bool
}

func (s *stubPersistentDNSCache) LoadDNSCache(string, string, uint16) ([]byte, time.Time, bool) {
	if !s.present {
		return nil, time.Time{}, false
	}
	return s.raw, s.expireAt, true
}

func (s *stubPersistentDNSCache) SaveDNSCache(string, string, uint16, []byte, time.Time) error {
	return nil
}

func (s *stubPersistentDNSCache) DeleteDNSCache(string, string, uint16, []byte) {
	s.present = false
	s.deleted = true
}

func (s *stubPersistentDNSCache) ClearDNSCache() error { return nil }

func TestLoadPersistentResponseEnforcesMaxCacheTTL(t *testing.T) {
	packed, err := responseWithTTL(3600).Pack()
	if err != nil {
		t.Fatal(err)
	}
	key := dnsCacheKey{
		Question:     mDNS.Question{Name: "example.com.", Qtype: mDNS.TypeA, Qclass: mDNS.ClassINET},
		transportTag: "remote",
	}

	// Lowering max_cache_ttl to 60s must invalidate a previously stored 3600s entry.
	store := &stubPersistentDNSCache{
		raw:      packed,
		expireAt: time.Now().Add(time.Hour),
		present:  true,
	}
	client := NewClient(ClientOptions{
		MaxCacheTTL: 60,
		DNSCache:    func() adapter.DNSCacheStore { return store },
	})
	client.dnsCache = store
	resp, _, _ := client.loadResponseWithOptions(key, adapter.DNSQueryOptions{})
	if resp != nil {
		t.Fatalf("expected cache miss when persistent TTL exceeds max_cache_ttl, got hit")
	}
	if !store.deleted {
		t.Fatalf("expected oversized persistent entry to be deleted")
	}

	// Previously stored 3600s entry with only 30s remaining is already ~3570s old and must be invalidated under 60s max_cache_ttl.
	store = &stubPersistentDNSCache{
		raw:      packed,
		expireAt: time.Now().Add(30 * time.Second),
		present:  true,
	}
	client.dnsCache = store
	resp, _, _ = client.loadResponseWithOptions(key, adapter.DNSQueryOptions{})
	if resp != nil || !store.deleted {
		t.Fatalf("expected aged 3600s entry to be invalidated under 60s max_cache_ttl, got resp=%v deleted=%v", resp != nil, store.deleted)
	}

	// Fresh entries stored within max_cache_ttl remain valid hits.
	packedShort, err := responseWithTTL(60).Pack()
	if err != nil {
		t.Fatal(err)
	}
	store = &stubPersistentDNSCache{
		raw:      packedShort,
		expireAt: time.Now().Add(30 * time.Second),
		present:  true,
	}
	client.dnsCache = store
	resp, ttl, stale := client.loadResponseWithOptions(key, adapter.DNSQueryOptions{})
	if resp == nil || stale || ttl > 60 {
		t.Fatalf("expected valid hit within max_cache_ttl, got resp=%v ttl=%d stale=%v", resp != nil, ttl, stale)
	}

	// disable_expire clamps returned TTL to max_cache_ttl (or rewrite_ttl when set).
	disableExpireClient := NewClient(ClientOptions{
		MaxCacheTTL:   60,
		DisableExpire: true,
		DNSCache:      func() adapter.DNSCacheStore { return store },
	})
	store = &stubPersistentDNSCache{
		raw:      packed,
		expireAt: time.Now().Add(time.Hour),
		present:  true,
	}
	disableExpireClient.dnsCache = store
	resp, _, _ = disableExpireClient.loadResponseWithOptions(key, adapter.DNSQueryOptions{})
	if resp == nil || computeTimeToLive(resp) != 60 {
		t.Fatalf("expected disable_expire response TTL clamped to 60, got resp=%v ttl=%d", resp != nil, computeTimeToLive(resp))
	}

	// Explicit rewrite_ttl higher than max_cache_ttl keeps matching entries valid.
	rewriteTTL := uint32(300)
	packedRewrite, err := responseWithTTL(300).Pack()
	if err != nil {
		t.Fatal(err)
	}
	store = &stubPersistentDNSCache{
		raw:      packedRewrite,
		expireAt: time.Now().Add(200 * time.Second),
		present:  true,
	}
	client.dnsCache = store
	resp, ttl, stale = client.loadResponseWithOptions(key, adapter.DNSQueryOptions{RewriteTTL: &rewriteTTL})
	if resp == nil || stale || ttl <= 60 {
		t.Fatalf("expected rewrite_ttl hit, got resp=%v ttl=%d stale=%v", resp != nil, ttl, stale)
	}
	resp, _, _ = disableExpireClient.loadResponseWithOptions(key, adapter.DNSQueryOptions{RewriteTTL: &rewriteTTL})
	if resp == nil || computeTimeToLive(resp) != 300 {
		t.Fatalf("expected disable_expire rewrite_ttl=300, got resp=%v ttl=%d", resp != nil, computeTimeToLive(resp))
	}
}
