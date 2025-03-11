package remote

import (
	"context"
	"crypto/sha256"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/outbound"
	providerAdapter "github.com/sagernet/sing-box/adapter/provider"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/trojan"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

type subscriptionCacheStub struct {
	adapter.CacheFile
	saved *adapter.SavedBinary
}

func (c *subscriptionCacheStub) LoadSubscription(string) *adapter.SavedBinary {
	return c.saved
}

func (c *subscriptionCacheStub) SaveSubscription(_ string, value *adapter.SavedBinary) error {
	cp := *value
	cp.Content = append([]byte(nil), value.Content...)
	cp.URLHash = append([]byte(nil), value.URLHash...)
	c.saved = &cp
	return nil
}

func TestProviderRemoteURLHash(t *testing.T) {
	t.Parallel()

	const providerURL = "https://example.com/provider"
	provider, err := NewProviderRemote(
		context.Background(),
		nil,
		log.NewNOPFactory(),
		"test",
		option.ProviderRemoteOptions{URL: providerURL},
	)
	require.NoError(t, err)
	require.Equal(t, sha256.Sum256([]byte(providerURL)), provider.(*ProviderRemote).urlHash)
}

func TestProviderRemoteRejectsCacheFromDifferentURL(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	logFactory := log.NewNOPFactory()
	logger := logFactory.NewLogger("test")
	providerURLHash := sha256.Sum256([]byte("https://example.com/new-provider"))
	provider := &ProviderRemote{
		Adapter: providerAdapter.NewAdapter(
			ctx,
			nil,
			nil,
			nil,
			logFactory,
			logger,
			"test",
			C.ProviderTypeRemote,
			option.ProviderHealthCheckOptions{},
		),
		ctx:     ctx,
		logger:  logger,
		urlHash: providerURLHash,
		cacheFile: &subscriptionCacheStub{saved: &adapter.SavedBinary{
			Content: []byte("invalid provider content must not be parsed"),
			URLHash: []byte("different URL hash"),
		}},
	}

	loaded, err := provider.loadCacheFile()
	require.NoError(t, err)
	require.False(t, loaded)
}

func newTestRemoteProviderEnv(t *testing.T, cache adapter.CacheFile) (context.Context, *outbound.Manager, map[string]*option.TrojanOutboundOptions) {
	t.Helper()
	captured := make(map[string]*option.TrojanOutboundOptions)
	outReg := outbound.NewRegistry()
	outbound.Register[option.TrojanOutboundOptions](outReg, C.TypeTrojan, func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.TrojanOutboundOptions) (adapter.Outbound, error) {
		optsCopy := options
		captured[tag] = &optsCopy
		return trojan.NewOutbound(ctx, router, logger, tag, options)
	})
	epReg := endpoint.NewRegistry()
	epMgr := endpoint.NewManager(epReg)
	outMgr := outbound.NewManager(outReg, epMgr, "")
	ctx := context.Background()
	ctx = service.ContextWith[adapter.OutboundRegistry](ctx, outReg)
	ctx = service.ContextWith[option.OutboundOptionsRegistry](ctx, outReg)
	ctx = service.ContextWith[adapter.EndpointRegistry](ctx, epReg)
	ctx = service.ContextWith[option.EndpointOptionsRegistry](ctx, epReg)
	ctx = service.ContextWith[adapter.OutboundManager](ctx, outMgr)
	ctx = service.ContextWith[adapter.EndpointManager](ctx, epMgr)
	if cache != nil {
		ctx = service.ContextWith[adapter.CacheFile](ctx, cache)
	}
	return ctx, outMgr, captured
}

func TestProviderRemoteCacheReappliesOverridesAndFilters(t *testing.T) {
	t.Parallel()
	const subBody = `{"outbounds":[` +
		`{"type":"trojan","tag":"alpha","server":"127.0.0.1","server_port":443,"password":"p","tls":{"enabled":true,"server_name":"a.example.com"}},` +
		`{"type":"trojan","tag":"beta","server":"127.0.0.1","server_port":443,"password":"p","tls":{"enabled":true,"server_name":"b.example.com"}}` +
		`]}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Etag", `"v1"`)
		_, _ = io.WriteString(w, subBody)
	}))
	defer server.Close()

	for _, withPath := range []bool{false, true} {
		name := "cache_file_only"
		if withPath {
			name = "path_and_cache_file"
		}
		t.Run(name, func(t *testing.T) {
			cache := &subscriptionCacheStub{}
			var cachePath string
			if withPath {
				cachePath = filepath.Join(t.TempDir(), "sub.json")
			}

			// First run: insecure=true, include=alpha.
			ctx1, _, captured1 := newTestRemoteProviderEnv(t, cache)
			p1Iface, err := NewProviderRemote(ctx1, nil, log.NewNOPFactory(), "sub", option.ProviderRemoteOptions{
				URL:         server.URL,
				Path:        cachePath,
				Include:     (*badoption.Regexp)(regexp.MustCompile("^alpha$")),
				OverrideTLS: &option.OverrideTLSOptions{Insecure: common.Ptr(true)},
			})
			require.NoError(t, err)
			p1 := p1Iface.(*ProviderRemote)
			p1.cacheFile = cache
			p1.httpClient = server.Client()
			require.NoError(t, p1.fetch(ctx1, true))
			require.Contains(t, captured1, "sub/alpha")
			require.NotContains(t, captured1, "sub/beta")
			require.True(t, captured1["sub/alpha"].TLS.Insecure)

			// Second run (offline cache restore): insecure=false, include=beta.
			ctx2, _, captured2 := newTestRemoteProviderEnv(t, cache)
			p2Iface, err := NewProviderRemote(ctx2, nil, log.NewNOPFactory(), "sub", option.ProviderRemoteOptions{
				URL:         server.URL,
				Path:        cachePath,
				Include:     (*badoption.Regexp)(regexp.MustCompile("^beta$")),
				OverrideTLS: &option.OverrideTLSOptions{Insecure: common.Ptr(false)},
			})
			require.NoError(t, err)
			p2 := p2Iface.(*ProviderRemote)
			p2.cacheFile = cache
			loaded, err := p2.loadCacheFile()
			require.NoError(t, err)
			require.True(t, loaded)
			require.NotContains(t, captured2, "sub/alpha")
			require.Contains(t, captured2, "sub/beta")
			require.False(t, captured2["sub/beta"].TLS.Insecure)
		})
	}
}

func TestProviderRemoteNotModifiedUpdatesPathAndHashTogether(t *testing.T) {
	t.Parallel()
	const subBody = `{"outbounds":[{"type":"trojan","tag":"alpha","server":"127.0.0.1","server_port":443,"password":"p","tls":{"enabled":true,"server_name":"a.example.com"}}]}`
	var step atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch step.Add(1) {
		case 1:
			w.Header().Set("Etag", `"v1"`)
			w.Header().Set("subscription-userinfo", "upload=1; download=2; total=100; expire=999")
			_, _ = io.WriteString(w, subBody)
		case 2:
			require.Equal(t, `"v1"`, r.Header.Get("If-None-Match"))
			w.Header().Set("subscription-userinfo", "upload=50; download=60; total=100; expire=999")
			w.WriteHeader(http.StatusNotModified)
		default:
			require.Equal(t, `"v1"`, r.Header.Get("If-None-Match"))
			// Intentionally omit subscription-userinfo header on 304.
			w.WriteHeader(http.StatusNotModified)
		}
	}))
	defer server.Close()

	cache := &subscriptionCacheStub{}
	cachePath := filepath.Join(t.TempDir(), "sub.json")
	ctx, _, _ := newTestRemoteProviderEnv(t, cache)
	pIface, err := NewProviderRemote(ctx, nil, log.NewNOPFactory(), "sub", option.ProviderRemoteOptions{
		URL:  server.URL,
		Path: cachePath,
	})
	require.NoError(t, err)
	p := pIface.(*ProviderRemote)
	p.cacheFile = cache
	p.httpClient = server.Client()

	// 1. Initial 200 OK.
	require.NoError(t, p.fetch(ctx, true))
	// 2. 304 with updated subscription-userinfo.
	require.NoError(t, p.fetch(ctx, false))
	require.Equal(t, int64(50), p.SubscriptionInfo().Upload)

	// Restart & reload from disk + cache must validate hash cleanly.
	ctxReload1, _, _ := newTestRemoteProviderEnv(t, cache)
	pReload1Iface, err := NewProviderRemote(ctxReload1, nil, log.NewNOPFactory(), "sub", option.ProviderRemoteOptions{
		URL:  server.URL,
		Path: cachePath,
	})
	require.NoError(t, err)
	pReload1 := pReload1Iface.(*ProviderRemote)
	pReload1.cacheFile = cache
	loaded, err := pReload1.loadCacheFile()
	require.NoError(t, err)
	require.True(t, loaded)
	require.Equal(t, int64(50), pReload1.SubscriptionInfo().Upload)

	// 3. 304 with omitted subscription-userinfo preserves prior subscription info.
	pReload1.httpClient = server.Client()
	require.NoError(t, pReload1.fetch(ctxReload1, false))
	require.Equal(t, int64(50), pReload1.SubscriptionInfo().Upload)

	// Restart & reload again must still validate hash cleanly and preserve subscription info.
	ctxReload2, _, _ := newTestRemoteProviderEnv(t, cache)
	pReload2Iface, err := NewProviderRemote(ctxReload2, nil, log.NewNOPFactory(), "sub", option.ProviderRemoteOptions{
		URL:  server.URL,
		Path: cachePath,
	})
	require.NoError(t, err)
	pReload2 := pReload2Iface.(*ProviderRemote)
	pReload2.cacheFile = cache
	loaded, err = pReload2.loadCacheFile()
	require.NoError(t, err)
	require.True(t, loaded)
	require.Equal(t, int64(50), pReload2.SubscriptionInfo().Upload)
}

func TestProviderRemoteNotModifiedWithoutPathPreservesSubscriptionInfo(t *testing.T) {
	t.Parallel()
	const subBody = `{"outbounds":[{"type":"trojan","tag":"alpha","server":"127.0.0.1","server_port":443,"password":"p","tls":{"enabled":true,"server_name":"a.example.com"}}]}`
	var step atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if step.Add(1) == 1 {
			w.Header().Set("Etag", `"v1"`)
			w.Header().Set("subscription-userinfo", "upload=7; download=8; total=100; expire=999")
			_, _ = io.WriteString(w, subBody)
			return
		}
		require.Equal(t, `"v1"`, r.Header.Get("If-None-Match"))
		w.WriteHeader(http.StatusNotModified)
	}))
	defer server.Close()

	cache := &subscriptionCacheStub{}
	ctx1, _, _ := newTestRemoteProviderEnv(t, cache)
	p1Iface, err := NewProviderRemote(ctx1, nil, log.NewNOPFactory(), "sub", option.ProviderRemoteOptions{URL: server.URL})
	require.NoError(t, err)
	p1 := p1Iface.(*ProviderRemote)
	p1.cacheFile = cache
	p1.httpClient = server.Client()
	require.NoError(t, p1.fetch(ctx1, true))
	require.NoError(t, p1.fetch(ctx1, false))
	require.Equal(t, int64(7), p1.SubscriptionInfo().Upload)

	ctx2, _, _ := newTestRemoteProviderEnv(t, cache)
	p2Iface, err := NewProviderRemote(ctx2, nil, log.NewNOPFactory(), "sub", option.ProviderRemoteOptions{URL: server.URL})
	require.NoError(t, err)
	p2 := p2Iface.(*ProviderRemote)
	p2.cacheFile = cache
	loaded, err := p2.loadCacheFile()
	require.NoError(t, err)
	require.True(t, loaded)
	require.Equal(t, int64(7), p2.SubscriptionInfo().Upload)
}

func TestProviderRemoteLegacyProcessedCacheForcesUnconditionalRefresh(t *testing.T) {
	t.Parallel()
	const rawBody = `{"outbounds":[{"type":"trojan","tag":"alpha","server":"127.0.0.1","server_port":443,"password":"p","tls":{"enabled":true,"server_name":"a.example.com"}}]}`
	const legacyProcessed = `{"outbounds":[{"type":"trojan","tag":"alpha","server":"127.0.0.1","server_port":443,"password":"p","tls":{"enabled":true,"insecure":true,"server_name":"a.example.com"}}]}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == `"old-etag"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("Etag", `"old-etag"`)
		_, _ = io.WriteString(w, rawBody)
	}))
	defer server.Close()

	cache := &subscriptionCacheStub{
		saved: &adapter.SavedBinary{
			Content:     []byte(legacyProcessed),
			LastEtag:    `"old-etag"`,
			LastUpdated: time.Now(),
		},
	}
	ctx, _, captured := newTestRemoteProviderEnv(t, cache)
	pIface, err := NewProviderRemote(ctx, nil, log.NewNOPFactory(), "sub", option.ProviderRemoteOptions{
		URL: server.URL,
	})
	require.NoError(t, err)
	p := pIface.(*ProviderRemote)
	p.cacheFile = cache
	p.httpClient = server.Client()

	loaded, err := p.loadCacheFile()
	require.NoError(t, err)
	require.True(t, loaded)
	// Legacy processed cache must drop ETag and lastUpdated so next fetch is unconditional.
	require.Empty(t, p.lastEtag)
	require.True(t, p.lastUpdated.IsZero())

	require.NoError(t, p.fetch(ctx, false))
	require.False(t, captured["sub/alpha"].TLS.Insecure)
	require.Equal(t, `"old-etag"`, p.lastEtag)
}
