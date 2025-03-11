package group

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"sync"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

func TestSelectorDefaultFromProvider(t *testing.T) {
	for _, testCase := range []struct {
		name          string
		outbounds     []string
		startSelected string
		afterFirst    string
	}{
		{name: "mixed", outbounds: []string{"bootstrap"}, startSelected: "bootstrap", afterFirst: "bootstrap"},
		{name: "provider only", startSelected: "Compatible", afterFirst: "first/a"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			env := newSelectorTestEnv(t)
			first := env.addProvider("first")
			second := env.addProvider("second")
			selector, err := env.start(option.SelectorOutboundOptions{
				GroupCommonOption: option.GroupCommonOption{Outbounds: testCase.outbounds, Providers: []string{"first", "second"}},
				Default:           "second/b",
			})
			require.NoError(t, err)
			require.Equal(t, testCase.startSelected, selected(selector))

			// The first provider is published even though the default is not there yet.
			first.load(t, "first/a")
			require.Contains(t, selector.All(), "first/a")
			require.Equal(t, testCase.afterFirst, selected(selector))

			// The bootstrap selection must not shadow the default once it arrives.
			second.load(t, "second/a", "second/b")
			require.Equal(t, "second/b", selected(selector))

			selector.finalizeProviderSelection()
			require.Equal(t, "second/b", selected(selector))
			require.Empty(t, env.logger.warnings())
		})
	}
}

func TestSelectorMissingProviderDefaultFallsBack(t *testing.T) {
	env := newSelectorTestEnv(t)
	first := env.addProvider("first")
	selector, err := env.start(option.SelectorOutboundOptions{
		GroupCommonOption: option.GroupCommonOption{Providers: []string{"first"}},
		Default:           "first/missing",
	})
	require.NoError(t, err)
	first.load(t, "first/a", "first/b")
	selector.finalizeProviderSelection()
	require.Equal(t, "first/a", selected(selector))
	require.Len(t, env.logger.warnings(), 1)
	require.Contains(t, env.logger.warnings()[0], "first/missing")

	// Finalizing again is a no-op.
	selector.finalizeProviderSelection()
	require.Len(t, env.logger.warnings(), 1)

	// The default appearing later does not take over the running selection.
	first.load(t, "first/a", "first/b", "first/missing")
	require.Equal(t, "first/a", selected(selector))
}

func TestSelectorRejectsUnreachableDefault(t *testing.T) {
	for _, testCase := range []struct {
		name    string
		options option.SelectorOutboundOptions
		message string
	}{
		{
			name:    "static",
			options: option.SelectorOutboundOptions{GroupCommonOption: option.GroupCommonOption{Outbounds: []string{"bootstrap"}}, Default: "missing"},
			message: "default outbound not found: missing",
		},
		{
			name:    "bare provider outbound",
			options: option.SelectorOutboundOptions{GroupCommonOption: option.GroupCommonOption{Providers: []string{"first"}}, Default: "a"},
			message: "<provider tag>/<outbound tag>",
		},
		{
			name:    "empty provider outbound tag",
			options: option.SelectorOutboundOptions{GroupCommonOption: option.GroupCommonOption{Providers: []string{"first"}}, Default: "first/"},
			message: "<provider tag>/<outbound tag>",
		},
		{
			name:    "unbound provider",
			options: option.SelectorOutboundOptions{GroupCommonOption: option.GroupCommonOption{Providers: []string{"first"}}, Default: "other/a"},
			message: "default outbound not found: other/a",
		},
		{
			name: "excluded",
			options: option.SelectorOutboundOptions{
				GroupCommonOption: option.GroupCommonOption{Providers: []string{"first"}, Exclude: testRegexp(`/a$`)},
				Default:           "first/a",
			},
			message: "excluded",
		},
		{
			name: "not included",
			options: option.SelectorOutboundOptions{
				GroupCommonOption: option.GroupCommonOption{Providers: []string{"first"}, Include: testRegexp(`/b$`)},
				Default:           "first/a",
			},
			message: "include",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			env := newSelectorTestEnv(t)
			env.addProvider("first")
			_, err := env.start(testCase.options)
			require.ErrorContains(t, err, testCase.message)
		})
	}
}

func TestSelectorUseAllProvidersDefault(t *testing.T) {
	env := newSelectorTestEnv(t)
	first := env.addProvider("first")
	second := env.addProvider("second")
	selector, err := env.start(option.SelectorOutboundOptions{
		GroupCommonOption: option.GroupCommonOption{UseAllProviders: true},
		Default:           "second/b",
	})
	require.NoError(t, err)
	first.load(t, "first/a")
	second.load(t, "second/a", "second/b")
	selector.finalizeProviderSelection()
	require.Equal(t, "second/b", selected(selector))
}

func TestSelectorImplicitCompatibleDefault(t *testing.T) {
	env := newSelectorTestEnv(t)
	first := env.addProvider("first")
	selector, err := env.start(option.SelectorOutboundOptions{
		GroupCommonOption: option.GroupCommonOption{Providers: []string{"first"}},
		Default:           "Compatible",
	})
	require.NoError(t, err)
	selector.finalizeProviderSelection()
	require.Equal(t, "Compatible", selected(selector))
	require.Empty(t, env.logger.warnings())
	first.load(t, "first/a")
	require.Equal(t, "first/a", selected(selector))
}

func TestSelectorProviderCacheCannotMaskInvalidDefault(t *testing.T) {
	for _, cached := range []string{"bootstrap", "first/a"} {
		t.Run(cached, func(t *testing.T) {
			env := newSelectorTestEnv(t)
			env.cacheFile.selected["select"] = cached
			first := env.addProvider("first")
			first.setOutbounds("first/a")
			_, err := env.start(option.SelectorOutboundOptions{
				GroupCommonOption: option.GroupCommonOption{Outbounds: []string{"bootstrap"}, Providers: []string{"first"}},
				Default:           "unbound/b",
			})
			require.ErrorContains(t, err, "default outbound not found: unbound/b")
		})
	}
}

func TestSelectorCachedSelectionBeatsDefault(t *testing.T) {
	for _, testCase := range []struct {
		name     string
		cached   string
		expected string
	}{
		{name: "provider outbound", cached: "second/a", expected: "second/a"},
		{name: "direct outbound", cached: "bootstrap", expected: "bootstrap"},
		{name: "gone", cached: "second/gone", expected: "second/b"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			env := newSelectorTestEnv(t)
			env.cacheFile.selected["select"] = testCase.cached
			first := env.addProvider("first")
			second := env.addProvider("second")
			selector, err := env.start(option.SelectorOutboundOptions{
				GroupCommonOption: option.GroupCommonOption{Outbounds: []string{"bootstrap"}, Providers: []string{"first", "second"}},
				Default:           "second/b",
			})
			require.NoError(t, err)
			first.load(t, "first/a")
			second.load(t, "second/a", "second/b")
			selector.finalizeProviderSelection()
			require.Equal(t, testCase.expected, selected(selector))
			require.Empty(t, env.logger.warnings())
		})
	}
}

func TestSelectorCachedSelectionWithMissingDefault(t *testing.T) {
	env := newSelectorTestEnv(t)
	env.cacheFile.selected["select"] = "first/b"
	first := env.addProvider("first")
	selector, err := env.start(option.SelectorOutboundOptions{
		GroupCommonOption: option.GroupCommonOption{Providers: []string{"first"}},
		Default:           "first/missing",
	})
	require.NoError(t, err)
	first.load(t, "first/a", "first/b")
	selector.finalizeProviderSelection()
	require.Equal(t, "first/b", selected(selector))
	// The missing default is still reported even though the cache covers it.
	require.Len(t, env.logger.warnings(), 1)
	require.Contains(t, env.logger.warnings()[0], "first/missing")
}

func TestSelectorMissingDefaultUsesFinalFirstMember(t *testing.T) {
	env := newSelectorTestEnv(t)
	first := env.addProvider("first")
	second := env.addProvider("second")
	selector, err := env.start(option.SelectorOutboundOptions{
		GroupCommonOption: option.GroupCommonOption{Providers: []string{"first", "second"}},
		Default:           "first/missing",
	})
	require.NoError(t, err)
	// Providers finish loading out of member order.
	second.load(t, "second/a")
	require.Equal(t, "second/a", selected(selector))
	first.load(t, "first/a")
	selector.finalizeProviderSelection()
	require.Equal(t, []string{"first/a", "second/a"}, selector.All())
	require.Equal(t, "first/a", selected(selector))
	require.Contains(t, env.logger.warnings()[0], "use first/a")
}

func TestSelectorStartSeesLoadedProviderOutbounds(t *testing.T) {
	env := newSelectorTestEnv(t)
	first := env.addProvider("first")
	// Like an inline provider, or a group created after providers have loaded,
	// the outbounds exist before Start and no update follows.
	first.setOutbounds("first/a", "first/b")
	selector, err := env.start(option.SelectorOutboundOptions{
		GroupCommonOption: option.GroupCommonOption{Outbounds: []string{"bootstrap"}, Providers: []string{"first"}},
		Default:           "first/b",
	})
	require.NoError(t, err)
	require.Equal(t, []string{"bootstrap", "first/a", "first/b"}, selector.All())
	require.Equal(t, "first/b", selected(selector))
	require.NoError(t, selector.Start(adapter.StartStatePostStart, env.scope))
	require.Equal(t, "first/b", selected(selector))
	require.Empty(t, env.logger.warnings())
}

func TestSelectorStaticCacheBypassesDefault(t *testing.T) {
	options := option.SelectorOutboundOptions{
		GroupCommonOption: option.GroupCommonOption{Outbounds: []string{"bootstrap", "proxy"}},
		Default:           "removed",
	}
	t.Run("cached", func(t *testing.T) {
		env := newSelectorTestEnv(t)
		env.addDirect("proxy")
		env.cacheFile.selected["select"] = "proxy"
		selector, err := env.start(options)
		require.NoError(t, err)
		require.Equal(t, "proxy", selected(selector))
	})
	t.Run("not cached", func(t *testing.T) {
		env := newSelectorTestEnv(t)
		env.addDirect("proxy")
		env.cacheFile.selected["select"] = "gone"
		_, err := env.start(options)
		require.ErrorContains(t, err, "default outbound not found: removed")
	})
}

func TestSelectorManualSelection(t *testing.T) {
	env := newSelectorTestEnv(t)
	first := env.addProvider("first")
	selector, err := env.start(option.SelectorOutboundOptions{
		GroupCommonOption: option.GroupCommonOption{Outbounds: []string{"bootstrap"}, Providers: []string{"first"}},
		Default:           "first/b",
	})
	require.NoError(t, err)

	// Choosing the bootstrap explicitly before providers load is kept.
	require.True(t, selector.SelectOutbound("bootstrap"))
	first.load(t, "first/a", "first/b", "first/c")
	selector.finalizeProviderSelection()
	require.Equal(t, "bootstrap", selected(selector))

	require.True(t, selector.SelectOutbound("first/c"))
	require.Equal(t, "first/c", env.cacheFile.selected["select"])
	require.False(t, selector.SelectOutbound("first/unknown"))
	require.Equal(t, "first/c", selected(selector))

	// The explicit selection comes back once its outbound reappears.
	first.load(t, "first/a", "first/b")
	require.Equal(t, "first/b", selected(selector))
	first.load(t, "first/a", "first/b", "first/c")
	require.Equal(t, "first/c", selected(selector))
}

func TestSelectorRuntimeRemoval(t *testing.T) {
	env := newSelectorTestEnv(t)
	first := env.addProvider("first")
	selector, err := env.start(option.SelectorOutboundOptions{
		GroupCommonOption: option.GroupCommonOption{Providers: []string{"first"}},
		Default:           "first/b",
	})
	require.NoError(t, err)
	first.load(t, "first/a", "first/b", "first/c")
	selector.finalizeProviderSelection()
	require.Equal(t, "first/b", selected(selector))

	// Removing both the selection and the default publishes the new members
	// and falls back to the first one instead of keeping a closed outbound.
	first.load(t, "first/a", "first/c")
	require.Equal(t, []string{"first/a", "first/c"}, selector.All())
	require.Equal(t, "first/a", selected(selector))
	require.Same(t, first.outbound("first/a"), selector.Selected("tcp"))
	require.Len(t, env.logger.warnings(), 1)

	// A replaced instance with the same tag is picked up.
	previous := selector.Selected("tcp")
	first.load(t, "first/a", "first/c")
	require.Equal(t, "first/a", selected(selector))
	require.NotSame(t, previous, selector.Selected("tcp"))
	require.Same(t, first.outbound("first/a"), selector.Selected("tcp"))

	// Losing every provider outbound falls back to Compatible; Compatible
	// leaving again is not reported.
	first.load(t)
	require.Equal(t, []string{"Compatible"}, selector.All())
	require.Equal(t, "Compatible", selected(selector))
	require.Len(t, env.logger.warnings(), 2)
	first.load(t, "first/a")
	require.Equal(t, "first/a", selected(selector))
	require.Len(t, env.logger.warnings(), 2)
}

func TestSelectorStaticGroupUnchanged(t *testing.T) {
	env := newSelectorTestEnv(t)
	env.addDirect("proxy")
	selector, err := env.start(option.SelectorOutboundOptions{
		GroupCommonOption: option.GroupCommonOption{Outbounds: []string{"bootstrap", "proxy"}},
		Default:           "proxy",
	})
	require.NoError(t, err)
	require.Equal(t, "proxy", selected(selector))
	require.NoError(t, selector.Start(adapter.StartStatePostStart, env.scope))
	require.Equal(t, "proxy", selected(selector))
	require.Empty(t, env.logger.warnings())
}

func TestSelectorPostStartFinalizes(t *testing.T) {
	env := newSelectorTestEnv(t)
	first := env.addProvider("first")
	selector, err := env.start(option.SelectorOutboundOptions{
		GroupCommonOption: option.GroupCommonOption{Outbounds: []string{"bootstrap"}, Providers: []string{"first"}},
		Default:           "first/b",
	})
	require.NoError(t, err)
	first.load(t, "first/a")
	require.NoError(t, selector.Start(adapter.StartStatePostStart, env.scope))
	require.Equal(t, "bootstrap", selected(selector))
	require.Len(t, env.logger.warnings(), 1)
	// Without finalizing, the default appearing now would still take over.
	first.load(t, "first/a", "first/b")
	require.Equal(t, "bootstrap", selected(selector))
}

func selected(selector *Selector) string {
	return selector.Selected("tcp").Tag()
}

func testRegexp(expression string) *badoption.Regexp {
	return (*badoption.Regexp)(regexp.MustCompile(expression))
}

type selectorTestEnv struct {
	ctx       context.Context
	outbounds *providerUpdateTestOutboundManager
	providers *selectorTestProviderManager
	cacheFile *selectorTestCacheFile
	logger    *selectorTestLogger
	scope     *adapter.Scope
}

func newSelectorTestEnv(t *testing.T) *selectorTestEnv {
	env := &selectorTestEnv{
		outbounds: &providerUpdateTestOutboundManager{outbounds: make(map[string]adapter.Outbound)},
		providers: &selectorTestProviderManager{},
		cacheFile: &selectorTestCacheFile{selected: make(map[string]string)},
		logger:    &selectorTestLogger{ContextLogger: logger.NOP()},
	}
	env.addDirect("Compatible")
	env.addDirect("bootstrap")
	ctx := service.ContextWith[adapter.OutboundManager](t.Context(), env.outbounds)
	ctx = service.ContextWith[adapter.ProviderManager](ctx, env.providers)
	ctx = service.ContextWith[adapter.CacheFile](ctx, env.cacheFile)
	env.ctx = ctx
	env.scope = adapter.NewScope(ctx, logger.NOP())
	t.Cleanup(func() { _ = env.scope.Close() })
	return env
}

func (e *selectorTestEnv) addDirect(tag string) {
	e.outbounds.outbounds[tag] = &preMatchTestOutbound{tag: tag}
}

// addProvider registers a provider that has not loaded yet, like a remote
// provider before its first download.
func (e *selectorTestEnv) addProvider(tag string) *selectorTestProvider {
	provider := &selectorTestProvider{tag: tag, outboundManager: e.outbounds}
	e.providers.providers = append(e.providers.providers, provider)
	return provider
}

func (e *selectorTestEnv) start(options option.SelectorOutboundOptions) (*Selector, error) {
	outbound, err := NewSelector(e.ctx, nil, e.logger, "select", options)
	if err != nil {
		return nil, err
	}
	selector := outbound.(*Selector)
	err = selector.Start(adapter.StartStateStart, e.scope)
	if err != nil {
		return nil, err
	}
	return selector, nil
}

type selectorTestProvider struct {
	adapter.Provider
	tag             string
	outboundManager *providerUpdateTestOutboundManager
	access          sync.Mutex
	outbounds       []adapter.Outbound
	callbacks       list.List[adapter.ProviderUpdateCallback]
}

func (p *selectorTestProvider) Tag() string {
	return p.tag
}

// setOutbounds replaces every outbound with a new instance, like a provider
// reload does, and registers it in the outbound manager.
func (p *selectorTestProvider) setOutbounds(tags ...string) {
	p.access.Lock()
	defer p.access.Unlock()
	for _, outbound := range p.outbounds {
		delete(p.outboundManager.outbounds, outbound.Tag())
	}
	p.outbounds = make([]adapter.Outbound, 0, len(tags))
	for _, tag := range tags {
		outbound := &preMatchTestOutbound{tag: tag}
		p.outbounds = append(p.outbounds, outbound)
		p.outboundManager.outbounds[tag] = outbound
	}
}

func (p *selectorTestProvider) outbound(tag string) adapter.Outbound {
	p.access.Lock()
	defer p.access.Unlock()
	for _, outbound := range p.outbounds {
		if outbound.Tag() == tag {
			return outbound
		}
	}
	return nil
}

func (p *selectorTestProvider) Outbounds() []adapter.Outbound {
	p.access.Lock()
	defer p.access.Unlock()
	return slices.Clone(p.outbounds)
}

func (p *selectorTestProvider) RegisterCallback(callback adapter.ProviderUpdateCallback) *list.Element[adapter.ProviderUpdateCallback] {
	p.access.Lock()
	defer p.access.Unlock()
	return p.callbacks.PushBack(callback)
}

func (p *selectorTestProvider) UnregisterCallback(element *list.Element[adapter.ProviderUpdateCallback]) {
	p.access.Lock()
	defer p.access.Unlock()
	p.callbacks.Remove(element)
}

// load replaces the provider outbounds and notifies the groups.
func (p *selectorTestProvider) load(t *testing.T, tags ...string) {
	t.Helper()
	p.setOutbounds(tags...)
	p.update(t)
}

func (p *selectorTestProvider) update(t *testing.T) {
	t.Helper()
	p.access.Lock()
	var callbacks []adapter.ProviderUpdateCallback
	for element := p.callbacks.Front(); element != nil; element = element.Next() {
		callbacks = append(callbacks, element.Value)
	}
	p.access.Unlock()
	require.NotEmpty(t, callbacks)
	for _, callback := range callbacks {
		require.NoError(t, callback(p.tag))
	}
}

type selectorTestProviderManager struct {
	adapter.ProviderManager
	providers []adapter.Provider
}

func (m *selectorTestProviderManager) Providers() []adapter.Provider {
	return m.providers
}

func (m *selectorTestProviderManager) Get(tag string) (adapter.Provider, bool) {
	for _, provider := range m.providers {
		if provider.Tag() == tag {
			return provider, true
		}
	}
	return nil, false
}

type selectorTestCacheFile struct {
	adapter.CacheFile
	selected map[string]string
}

func (c *selectorTestCacheFile) LoadSelected(group string) string {
	return c.selected[group]
}

func (c *selectorTestCacheFile) StoreSelected(group string, selected string) error {
	c.selected[group] = selected
	return nil
}

type selectorTestLogger struct {
	logger.ContextLogger
	access   sync.Mutex
	messages []string
}

func (l *selectorTestLogger) Warn(args ...any) {
	l.access.Lock()
	defer l.access.Unlock()
	l.messages = append(l.messages, fmt.Sprint(args...))
}

func (l *selectorTestLogger) warnings() []string {
	l.access.Lock()
	defer l.access.Unlock()
	return slices.Clone(l.messages)
}

func TestCompatibleFallbackRejectsIndirectCycle(t *testing.T) {
	t.Parallel()
	env := newSelectorTestEnv(t)
	emptyProvider := env.addProvider("empty")

	// Register a custom "Compatible" selector that depends on "proxy-group".
	compatibleSelector, err := NewSelector(
		env.ctx,
		nil,
		env.logger,
		"Compatible",
		option.SelectorOutboundOptions{
			GroupCommonOption: option.GroupCommonOption{
				Outbounds: []string{"proxy-group"},
			},
		},
	)
	require.NoError(t, err)
	env.outbounds.outbounds["Compatible"] = compatibleSelector

	// "proxy-group" binds an empty provider; falling back to "Compatible" would form proxy-group -> Compatible -> proxy-group.
	_, _, _, err = collectProviderOutbounds(
		"proxy-group",
		"",
		nil,
		env.outbounds,
		map[string]adapter.Provider{"empty": emptyProvider},
		[]string{"empty"},
		nil,
		nil,
		nil,
	)
	require.ErrorContains(t, err, "cannot reference proxy-group")
}
