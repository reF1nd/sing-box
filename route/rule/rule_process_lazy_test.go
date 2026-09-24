package rule

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/common/logger"

	"github.com/stretchr/testify/require"
)

func lazyProcessMetadata(calls *atomic.Int32) adapter.InboundContext {
	return adapter.InboundContext{
		ProcessInfo: &adapter.ConnectionOwner{UserId: 10366, AndroidPackageNames: []string{"app.one"}},
		ProcessInfoResolver: sync.OnceValue(func() *adapter.ConnectionOwner {
			calls.Add(1)
			return &adapter.ConnectionOwner{UserId: 10366, AndroidPackageNames: []string{"app.one"}, ProcessPath: "/system/bin/netd"}
		}),
	}
}

func TestLazyProcessRuleMatchers(t *testing.T) {
	regex, err := NewProcessPathRegexItem([]string{"/system/bin/(netd|helper)$"})
	require.NoError(t, err)
	for _, item := range []RuleItem{NewProcessItem([]string{"netd"}), NewProcessPathItem([]string{"/system/bin/netd"}), regex} {
		t.Run(item.String(), func(t *testing.T) {
			var calls atomic.Int32
			metadata := lazyProcessMetadata(&calls)
			require.True(t, item.Match(&metadata))
			require.EqualValues(t, 1, calls.Load())
			require.True(t, item.Match(&metadata))
			require.EqualValues(t, 1, calls.Load())
		})
	}
}

func TestLazyProcessMetadataCopiesShareLookup(t *testing.T) {
	var calls atomic.Int32
	metadata := lazyProcessMetadata(&calls)
	item := NewProcessItem([]string{"netd"})
	var group sync.WaitGroup
	for range 16 {
		copyMetadata := metadata
		group.Go(func() { require.True(t, item.Match(&copyMetadata)) })
	}
	group.Wait()
	require.EqualValues(t, 1, calls.Load())
	require.Empty(t, metadata.ProcessInfo.ProcessPath)
}

func TestLazyProcessRuleSetUpdate(t *testing.T) {
	s := &LocalRuleSet{abstractRuleSet: abstractRuleSet{ctx: context.Background(), logger: logger.NOP(), tag: "apps"}}
	err := s.reloadRules([]option.HeadlessRule{{Type: C.RuleTypeDefault, DefaultOptions: option.DefaultHeadlessRule{PackageName: badoption.Listable[string]{"app.one"}}}}, s)
	require.NoError(t, err)
	var calls atomic.Int32
	metadata := lazyProcessMetadata(&calls)
	require.True(t, s.Match(&metadata))
	require.Zero(t, calls.Load())
	// No router callback or precomputed requirement flag is needed: the new
	// matcher resolves paths even for metadata prepared before the update.
	err = s.reloadRules([]option.HeadlessRule{{Type: C.RuleTypeDefault, DefaultOptions: option.DefaultHeadlessRule{ProcessName: badoption.Listable[string]{"netd"}}}}, s)
	require.NoError(t, err)
	require.True(t, s.Match(&metadata))
	require.EqualValues(t, 1, calls.Load())
}

func TestLazyProcessPackagePathCompatibility(t *testing.T) {
	if !C.IsAndroid {
		t.Skip("Android process_path also accepts package names")
	}
	var calls atomic.Int32
	metadata := lazyProcessMetadata(&calls)
	require.True(t, NewProcessPathItem([]string{"app.one"}).Match(&metadata))
	require.Zero(t, calls.Load())
}

func TestLazyProcessDNSRule(t *testing.T) {
	r, err := NewDefaultDNSRule(context.Background(), logger.NOP(), option.DefaultDNSRule{
		RawDefaultDNSRule: option.RawDefaultDNSRule{ProcessName: []string{"netd"}},
		DNSRuleAction:     option.DNSRuleAction{Action: C.RuleActionTypeReject},
	}, false)
	require.NoError(t, err)
	var calls atomic.Int32
	metadata := lazyProcessMetadata(&calls)
	require.True(t, r.Match(&metadata))
	require.EqualValues(t, 1, calls.Load())
}

func TestLazyProcessLogicalRule(t *testing.T) {
	r, err := NewHeadlessRule(context.Background(), option.HeadlessRule{
		Type: C.RuleTypeLogical,
		LogicalOptions: option.LogicalHeadlessRule{Mode: C.LogicalTypeAnd, Rules: []option.HeadlessRule{
			{Type: C.RuleTypeDefault, DefaultOptions: option.DefaultHeadlessRule{PackageName: badoption.Listable[string]{"app.one"}}},
			{Type: C.RuleTypeDefault, DefaultOptions: option.DefaultHeadlessRule{ProcessPath: badoption.Listable[string]{"/system/bin/netd"}}},
		}},
	})
	require.NoError(t, err)
	var calls atomic.Int32
	metadata := lazyProcessMetadata(&calls)
	require.True(t, r.Match(&metadata))
	require.EqualValues(t, 1, calls.Load())
}
