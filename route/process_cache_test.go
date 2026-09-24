package route

import (
	"context"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/process"
	"github.com/sagernet/sing-box/log"
	R "github.com/sagernet/sing-box/route/rule"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/contrab/freelru"
	"github.com/sagernet/sing/contrab/maphash"

	"github.com/stretchr/testify/require"
)

type testOwnerSearcher struct {
	ownerCalls atomic.Int32
	fullCalls  atomic.Int32
	lookup     func(context.Context, string, netip.AddrPort, netip.AddrPort, process.LookupMode) (*adapter.ConnectionOwner, error)
}

func (s *testOwnerSearcher) FindProcessInfo(ctx context.Context, network string, source, destination netip.AddrPort) (*adapter.ConnectionOwner, error) {
	return s.FindProcessInfoMode(ctx, network, source, destination, process.LookupFull)
}

func (s *testOwnerSearcher) FindProcessInfoMode(ctx context.Context, network string, source, destination netip.AddrPort, mode process.LookupMode) (*adapter.ConnectionOwner, error) {
	if mode == process.LookupFull {
		s.fullCalls.Add(1)
	} else {
		s.ownerCalls.Add(1)
	}
	if s.lookup != nil {
		return s.lookup(ctx, network, source, destination, mode)
	}
	info := &adapter.ConnectionOwner{UserId: 10366, UserName: "app", PackageNames: []string{"app.one"}}
	if mode == process.LookupFull {
		info.ProcessPaths = []string{"/system/bin/netd", "/system/bin/helper"}
	}
	return info, nil
}

func (s *testOwnerSearcher) ResetCache()  {}
func (s *testOwnerSearcher) Close() error { return nil }

func newOwnerTestRouter(t *testing.T) (*Router, *testOwnerSearcher, adapter.InboundContext) {
	t.Helper()
	searcher := &testOwnerSearcher{}
	cache, err := freelru.New[processCacheKey, processCacheEntry](256, maphash.NewHasher[processCacheKey]().Hash32, true)
	require.NoError(t, err)
	cache.SetLifetime(200 * time.Millisecond)
	r := &Router{logger: log.NewNOPFactory().NewLogger("test"), processSearcher: searcher, processCache: cache, processLookupMode: process.LookupOwner}
	return r, searcher, adapter.InboundContext{Network: "udp", Source: M.ParseSocksaddr("127.0.0.1:12345"), Destination: M.ParseSocksaddr("1.1.1.1:53")}
}

func TestOwnerLookupDefersPathsUntilRuleMatch(t *testing.T) {
	r, s, metadata := newOwnerTestRouter(t)
	r.searchProcessInfo(context.Background(), &metadata)
	require.EqualValues(t, 1, s.ownerCalls.Load())
	require.Zero(t, s.fullCalls.Load())
	require.True(t, R.NewPackageNameItem([]string{"app.one"}).Match(&metadata))
	require.Zero(t, s.fullCalls.Load())
	copyMetadata := metadata
	// DNS clears Destination before rule matching; the deferred lookup must
	// continue to use the original socket tuple.
	metadata.Destination = M.Socksaddr{}
	s.lookup = func(_ context.Context, network string, source, destination netip.AddrPort, mode process.LookupMode) (*adapter.ConnectionOwner, error) {
		require.Equal(t, "udp", network)
		require.Equal(t, netip.MustParseAddrPort("127.0.0.1:12345"), source)
		require.Equal(t, netip.MustParseAddrPort("1.1.1.1:53"), destination)
		require.Equal(t, process.LookupFull, mode)
		return &adapter.ConnectionOwner{UserId: 10366, ProcessPaths: []string{"/system/bin/netd", "/system/bin/helper"}}, nil
	}
	require.True(t, R.NewProcessItem([]string{"helper"}).Match(&metadata))
	require.True(t, R.NewProcessPathItem([]string{"/system/bin/netd"}).Match(&copyMetadata))
	require.EqualValues(t, 1, s.fullCalls.Load())
	// A new metadata object may reuse the owner cache, then upgrade through
	// the separately keyed full cache without another procfs lookup.
	_, _, next := newOwnerTestRouter(t)
	r.searchProcessInfo(context.Background(), &next)
	require.True(t, R.NewProcessItem([]string{"netd"}).Match(&next))
	require.EqualValues(t, 1, s.ownerCalls.Load())
	require.EqualValues(t, 1, s.fullCalls.Load())
}

func TestProvidedProcessOwnerIsNotReplaced(t *testing.T) {
	r, s, metadata := newOwnerTestRouter(t)
	metadata.ProcessInfo = &adapter.ConnectionOwner{UserId: 42, ProcessPaths: []string{"/provided"}}
	r.searchProcessInfo(context.Background(), &metadata)
	require.True(t, R.NewProcessPathItem([]string{"/provided"}).Match(&metadata))
	require.Zero(t, s.ownerCalls.Load())
	require.Zero(t, s.fullCalls.Load())
}

func TestFullLookupRemainsEager(t *testing.T) {
	r, s, metadata := newOwnerTestRouter(t)
	r.processLookupMode = process.LookupFull
	r.searchProcessInfo(context.Background(), &metadata)
	require.NotEmpty(t, metadata.ProcessInfo.ProcessPaths)
	require.Nil(t, metadata.ProcessInfoResolver)
	require.EqualValues(t, 1, s.fullCalls.Load())
}

func TestProcessLookupDoesNotCacheCanceledResult(t *testing.T) {
	r, s, metadata := newOwnerTestRouter(t)
	s.lookup = func(ctx context.Context, _ string, _, _ netip.AddrPort, _ process.LookupMode) (*adapter.ConnectionOwner, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return &adapter.ConnectionOwner{UserId: 42, UserName: "test"}, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := r.findProcessInfoCached(ctx, metadata.Network, metadata.Source.AddrPort(), metadata.Destination.AddrPort())
	require.ErrorIs(t, err, context.Canceled)
	_, err = r.findProcessInfoCached(context.Background(), metadata.Network, metadata.Source.AddrPort(), metadata.Destination.AddrPort())
	require.NoError(t, err)
	require.EqualValues(t, 2, s.ownerCalls.Load())
}

func TestProcessCacheResetDiscardsInFlightResult(t *testing.T) {
	r, s, metadata := newOwnerTestRouter(t)
	started, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	s.lookup = func(context.Context, string, netip.AddrPort, netip.AddrPort, process.LookupMode) (*adapter.ConnectionOwner, error) {
		if s.ownerCalls.Load() == 1 {
			close(started)
			<-release
		}
		return &adapter.ConnectionOwner{UserId: 42, UserName: "test"}, nil
	}
	go func() {
		defer close(done)
		_, _ = r.findProcessInfoCached(context.Background(), metadata.Network, metadata.Source.AddrPort(), metadata.Destination.AddrPort())
	}()
	<-started
	r.processCacheGeneration.Add(1)
	r.processCache.Purge()
	close(release)
	<-done
	_, err := r.findProcessInfoCached(context.Background(), metadata.Network, metadata.Source.AddrPort(), metadata.Destination.AddrPort())
	require.NoError(t, err)
	require.EqualValues(t, 2, s.ownerCalls.Load())
}
