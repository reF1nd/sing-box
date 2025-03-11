package group

import (
	"context"
	"io"
	"net"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/interrupt"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

func RegisterSelector(registry *outbound.Registry) {
	outbound.Register[option.SelectorOutboundOptions](registry, C.TypeSelector, NewSelector)
}

var (
	_ adapter.PreMatchOutboundGroup = (*Selector)(nil)
	_ adapter.Referrer              = (*Selector)(nil)
)

type Selector struct {
	outbound.Adapter
	ctx                          context.Context
	outbound                     adapter.OutboundManager
	logger                       logger.ContextLogger
	tags                         []string
	defaultTag                   string
	outbounds                    map[string]adapter.Outbound
	selected                     common.TypedValue[adapter.Outbound]
	history                      *urltest.HistoryStorage
	interruptGroup               *interrupt.Group
	interruptExternalConnections bool
	stateAccess                  sync.RWMutex
	providerAccess               sync.Mutex

	provider       adapter.ProviderManager
	providers      map[string]adapter.Provider
	outboundsCache map[string][]adapter.Outbound

	providerTags    []string
	exclude         *regexp.Regexp
	include         *regexp.Regexp
	useAllProviders bool

	// preferredTag and initialSelection are guarded by providerAccess.
	// preferredTag is the last explicit selection, restored from the cache file
	// or set by SelectOutbound, and wins whenever it is a member of the group.
	preferredTag string
	// initialSelection stays set until providers finish their first load, so the
	// bootstrap selection made in Start does not shadow a default from a provider.
	initialSelection bool
}

func NewSelector(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.SelectorOutboundOptions) (adapter.Outbound, error) {
	outbound := &Selector{
		Adapter:                      outbound.NewAdapter(C.TypeSelector, tag, []string{N.NetworkTCP, N.NetworkUDP}, options.Outbounds),
		ctx:                          ctx,
		outbound:                     service.FromContext[adapter.OutboundManager](ctx),
		logger:                       logger,
		tags:                         options.Outbounds,
		defaultTag:                   options.Default,
		outbounds:                    make(map[string]adapter.Outbound),
		history:                      service.PtrFromContext[urltest.HistoryStorage](ctx),
		interruptGroup:               interrupt.NewGroup(),
		interruptExternalConnections: options.InterruptExistConnections,

		provider:       service.FromContext[adapter.ProviderManager](ctx),
		providers:      make(map[string]adapter.Provider),
		outboundsCache: make(map[string][]adapter.Outbound),

		providerTags:    options.Providers,
		exclude:         (*regexp.Regexp)(options.Exclude),
		include:         (*regexp.Regexp)(options.Include),
		useAllProviders: options.UseAllProviders,
	}
	for i, tag := range outbound.tags {
		if slices.Contains(outbound.tags[:i], tag) {
			return nil, E.New("duplicate tag: ", tag)
		}
	}
	return outbound, nil
}

func (s *Selector) Dependencies() []string {
	var providerTags []string
	if !s.useAllProviders {
		providerTags = s.providerTags
	}
	return providerDependencies(
		s.Tag(),
		s.Adapter.Dependencies(),
		s.provider,
		providerTags,
		s.useAllProviders,
		s.exclude,
		s.include,
	)
}

func (s *Selector) Network() []string {
	selected := s.selected.Load()
	if selected == nil {
		return []string{N.NetworkTCP, N.NetworkUDP}
	}
	return selected.Network()
}

func (s *Selector) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	switch stage {
	case adapter.StartStateStart:
		if err := s.start(scope); err != nil {
			return err
		}
		if notifier, ok := s.provider.(adapter.ProviderStartNotifier); ok && len(s.providerTags) > 0 {
			notifier.OnProvidersStarted(func() {
				if scope.Context().Err() == nil {
					s.finalizeProviderSelection()
				}
			})
		}
	case adapter.StartStatePostStart:
		// Provider managers without a startup notification use the lifecycle stage.
		s.finalizeProviderSelection()
	}
	return nil
}

func (s *Selector) start(scope *adapter.Scope) error {
	s.providerAccess.Lock()
	defer s.providerAccess.Unlock()
	if s.useAllProviders {
		var providerTags []string
		for _, provider := range s.provider.Providers() {
			providerTags = append(providerTags, provider.Tag())
			s.providers[provider.Tag()] = provider
		}
		s.providerTags = providerTags
	} else {
		for i, tag := range s.providerTags {
			provider, loaded := s.provider.Get(tag)
			if !loaded {
				return E.New("outbound provider ", i, " not found: ", tag)
			}
			s.providers[tag] = provider
		}
	}
	directTags := s.Adapter.Dependencies()
	if len(directTags)+len(s.providerTags) == 0 {
		return E.New("missing outbound and provider tags")
	}
	// Register before collecting: an update racing with Start waits for
	// providerAccess and is applied on top of the snapshot below.
	for _, providerTag := range s.providerTags {
		p := s.providers[providerTag]
		element := p.RegisterCallback(s.onProviderUpdated)
		scope.Add(func() error { p.UnregisterCallback(element); return nil })
	}
	// Outbounds a provider already holds (inline providers, or providers loaded
	// before this group was created) are members from the start.
	tags, outbounds, outboundsCache, err := collectProviderOutbounds(
		s.Tag(),
		"",
		directTags,
		s.outbound,
		s.providers,
		s.providerTags,
		s.outboundsCache,
		s.exclude,
		s.include,
	)
	if err != nil {
		return err
	}
	outboundByTag := make(map[string]adapter.Outbound, len(outbounds))
	for _, detour := range outbounds {
		outboundByTag[detour.Tag()] = detour
	}
	if s.Tag() != "" {
		cacheFile := service.FromContext[adapter.CacheFile](s.ctx)
		if cacheFile != nil {
			s.preferredTag = cacheFile.LoadSelected(s.Tag())
		}
	}
	// Static selectors have always accepted a restored selection even when
	// their configured default no longer exists.
	if _, restored := outboundByTag[s.preferredTag]; len(s.providerTags) != 0 || !restored {
		err = s.checkDefault(directTags)
		if err != nil {
			return err
		}
	}
	// Other provider outbounds arrive through callbacks after Start, so the
	// selection made here may only be a bootstrap until the providers have loaded.
	s.initialSelection = len(s.providerTags) > 0
	selected := s.outboundSelect(outboundByTag, tags)
	s.stateAccess.Lock()
	s.tags, s.outbounds, s.outboundsCache = tags, outboundByTag, outboundsCache
	s.selected.Store(selected)
	s.stateAccess.Unlock()
	return nil
}

func (s *Selector) All() []string {
	s.stateAccess.RLock()
	defer s.stateAccess.RUnlock()
	return slices.Clone(s.tags)
}

func (s *Selector) Selected(network string) adapter.Outbound {
	return s.selected.Load()
}

func (s *Selector) AttachConnection(closer io.Closer) func() {
	return s.interruptGroup.Add(closer, true)
}

func (s *Selector) References() ([]string, []string) {
	selected := s.selected.Load()
	if selected == nil {
		tags := s.All()
		if len(tags) == 0 {
			return nil, nil
		}
		return tags[:1], nil
	}
	return []string{selected.Tag()}, nil
}

func (s *Selector) SelectPreMatchOutbound(metadata *adapter.InboundContext, selectOutbound func(adapter.Outbound) (adapter.Outbound, adapter.PreMatchAction)) (adapter.Outbound, adapter.PreMatchAction) {
	return selectOutbound(s.selected.Load())
}

func (s *Selector) SelectOutbound(tag string) bool {
	s.providerAccess.Lock()
	s.stateAccess.RLock()
	detour, loaded := s.outbounds[tag]
	s.stateAccess.RUnlock()
	if !loaded {
		s.providerAccess.Unlock()
		return false
	}
	s.preferredTag = tag
	if s.selected.Swap(detour) == detour {
		s.providerAccess.Unlock()
		return true
	}
	if s.Tag() != "" {
		cacheFile := service.FromContext[adapter.CacheFile](s.ctx)
		if cacheFile != nil {
			err := cacheFile.StoreSelected(s.Tag(), tag)
			if err != nil {
				s.logger.Error("store selected: ", err)
			}
		}
	}
	s.providerAccess.Unlock()
	s.interruptGroup.Interrupt(s.interruptExternalConnections)
	if s.history != nil {
		s.history.NotifyUpdated()
	}
	return true
}

func (s *Selector) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	conn, err := s.selected.Load().DialContext(ctx, network, destination)
	if err != nil {
		return nil, err
	}
	return s.interruptGroup.NewConn(conn, interrupt.IsExternalConnectionFromContext(ctx), interrupt.IsProviderConnectionFromContext(ctx)), nil
}

func (s *Selector) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	conn, err := s.selected.Load().ListenPacket(ctx, destination)
	if err != nil {
		return nil, err
	}
	return s.interruptGroup.NewPacketConn(conn, interrupt.IsExternalConnectionFromContext(ctx), interrupt.IsProviderConnectionFromContext(ctx)), nil
}

func RealTag(detour adapter.Outbound, network string) string {
	for {
		group, isGroup := detour.(adapter.OutboundGroup)
		if !isGroup {
			return detour.Tag()
		}
		detour = group.Selected(network)
		if detour == nil {
			return ""
		}
	}
}

func (s *Selector) onProviderUpdated(tag string) error {
	s.providerAccess.Lock()
	tags, outbounds, outboundsCache, err := collectProviderOutbounds(
		s.Tag(),
		tag,
		s.Adapter.Dependencies(),
		s.outbound,
		s.providers,
		s.providerTags,
		s.outboundsCache,
		s.exclude,
		s.include,
	)
	if err != nil {
		s.providerAccess.Unlock()
		return E.Cause(err, s.Tag())
	}
	outboundByTag := make(map[string]adapter.Outbound, len(outbounds))
	for _, detour := range outbounds {
		outboundByTag[detour.Tag()] = detour
	}
	s.stateAccess.Lock()
	detour := s.outboundSelect(outboundByTag, tags)
	s.tags, s.outbounds, s.outboundsCache = tags, outboundByTag, outboundsCache
	previous := s.selected.Swap(detour)
	s.stateAccess.Unlock()
	initialSelection := s.initialSelection
	s.providerAccess.Unlock()
	if previous != detour {
		// The implicit Compatible fallback leaving the group is not worth a warning.
		if !initialSelection && previous != nil && previous.Tag() != "Compatible" {
			if _, loaded := outboundByTag[previous.Tag()]; !loaded {
				s.logger.Warn("selected outbound removed: ", previous.Tag(), ", switch to ", detour.Tag())
			}
		}
		s.interruptGroup.Interrupt(s.interruptExternalConnections)
		if s.history != nil {
			s.history.NotifyUpdated()
		}
	}
	return nil
}

// finalizeProviderSelection ends the initial selection phase once providers
// have finished their first load. A default that is still missing is reported
// instead of failing, because provider outbounds come from external data.
func (s *Selector) finalizeProviderSelection() {
	s.providerAccess.Lock()
	defer s.providerAccess.Unlock()
	if !s.initialSelection {
		return
	}
	s.initialSelection = false
	if s.defaultTag == "" {
		return
	}
	s.stateAccess.RLock()
	_, loaded := s.outbounds[s.defaultTag]
	s.stateAccess.RUnlock()
	selected := s.selected.Load()
	if loaded || selected == nil {
		return
	}
	s.logger.Warn("default outbound not found after loading providers: ", s.defaultTag, ", use ", selected.Tag())
}

// checkDefault rejects default tags that can never become a member: provider
// outbounds are always tagged "<provider tag>/<outbound tag>" and filtered by
// exclude and include, so only a missing provider outbound is left to runtime.
func (s *Selector) checkDefault(directTags []string) error {
	if s.defaultTag == "" || slices.Contains(directTags, s.defaultTag) {
		return nil
	}
	if len(s.providerTags) == 0 {
		return E.New("default outbound not found: ", s.defaultTag)
	}
	// A provider-only selector includes Compatible whenever it has no members.
	if len(directTags) == 0 && s.defaultTag == "Compatible" {
		return nil
	}
	if !slices.ContainsFunc(s.providerTags, func(providerTag string) bool {
		outboundTag, found := strings.CutPrefix(s.defaultTag, providerTag+"/")
		return found && outboundTag != ""
	}) {
		return E.New("default outbound not found: ", s.defaultTag, " (provider outbounds must be referenced as <provider tag>/<outbound tag>)")
	}
	if s.exclude != nil && s.exclude.MatchString(s.defaultTag) {
		return E.New("default outbound is excluded by exclude: ", s.defaultTag)
	}
	if s.include != nil && !s.include.MatchString(s.defaultTag) {
		return E.New("default outbound is not matched by include: ", s.defaultTag)
	}
	return nil
}

// outboundSelect picks the explicit selection first, then the default, then the
// first member. While providers are still loading the bootstrap selection is
// ignored, so the result matches the final member list; afterwards the current
// selection is kept over the default so that provider updates do not switch it.
func (s *Selector) outboundSelect(outbounds map[string]adapter.Outbound, tags []string) adapter.Outbound {
	candidates := []string{s.preferredTag}
	if !s.initialSelection {
		if previous := s.selected.Load(); previous != nil {
			candidates = append(candidates, previous.Tag())
		}
	}
	candidates = append(candidates, s.defaultTag)
	for _, tag := range candidates {
		if tag == "" {
			continue
		}
		if detour, loaded := outbounds[tag]; loaded {
			return detour
		}
	}
	return outbounds[tags[0]]
}
