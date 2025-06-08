package group

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/interrupt"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/contrab/freelru"
	"github.com/sagernet/sing/contrab/maphash"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"

	"golang.org/x/net/publicsuffix"
)

func RegisterLoadBalance(registry *outbound.Registry) {
	outbound.Register[option.LoadBalanceOutboundOptions](registry, C.TypeLoadBalance, NewLoadBalance)
}

var (
	_ adapter.PreMatchOutboundGroup   = (*LoadBalance)(nil)
	_ adapter.InterfaceUpdateListener = (*LoadBalance)(nil)
)

const (
	StrategyRoundRobin        = "round-robin"
	StrategyConsistentHashing = "consistent-hashing"
	StrategyStickySessions    = "sticky-sessions"
)

type LoadBalance struct {
	outbound.Adapter
	ctx                 context.Context
	router              adapter.Router
	outbound            adapter.OutboundManager
	connection          adapter.ConnectionManager
	logger              log.ContextLogger
	tags                []string
	link                string
	interval            time.Duration
	idleTimeout         time.Duration
	ttl                 time.Duration
	group               *LoadBalanceGroup
	strategy            string
	providerAccess      sync.Mutex
	providerUpdateCheck providerUpdateCheckScheduler

	provider       adapter.ProviderManager
	providers      map[string]adapter.Provider
	outboundsCache map[string][]adapter.Outbound

	providerTags    []string
	exclude         *regexp.Regexp
	include         *regexp.Regexp
	useAllProviders bool
}

func NewLoadBalance(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.LoadBalanceOutboundOptions) (adapter.Outbound, error) {
	strategy := options.Strategy
	if strategy == "" {
		strategy = StrategyRoundRobin
	}
	switch strategy {
	case StrategyRoundRobin, StrategyConsistentHashing, StrategyStickySessions:
	default:
		return nil, E.New("load-balance strategy not found: ", strategy)
	}
	outbound := &LoadBalance{
		Adapter:     outbound.NewAdapter(C.TypeLoadBalance, tag, []string{N.NetworkTCP, N.NetworkUDP}, options.Outbounds),
		ctx:         ctx,
		router:      router,
		outbound:    service.FromContext[adapter.OutboundManager](ctx),
		connection:  service.FromContext[adapter.ConnectionManager](ctx),
		logger:      logger,
		tags:        options.Outbounds,
		link:        options.URL,
		interval:    time.Duration(options.Interval),
		ttl:         time.Duration(options.TTL),
		idleTimeout: time.Duration(options.IdleTimeout),
		strategy:    strategy,

		provider:       service.FromContext[adapter.ProviderManager](ctx),
		providers:      make(map[string]adapter.Provider),
		outboundsCache: make(map[string][]adapter.Outbound),

		providerTags:    options.Providers,
		exclude:         (*regexp.Regexp)(options.Exclude),
		include:         (*regexp.Regexp)(options.Include),
		useAllProviders: options.UseAllProviders,
	}
	return outbound, nil
}

func (s *LoadBalance) Start() error {
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
	if len(s.tags)+len(s.providerTags) == 0 {
		return E.New("missing outbound and provider tags")
	}

	outbounds := make([]adapter.Outbound, 0, len(s.tags))
	for i, tag := range s.tags {
		detour, loaded := s.outbound.Outbound(tag)
		if !loaded {
			return E.New("outbound ", i, " not found: ", tag)
		}
		outbounds = append(outbounds, detour)
	}
	if len(s.tags) == 0 {
		detour, _ := s.outbound.Outbound("Compatible")
		s.tags = append(s.tags, detour.Tag())
		outbounds = append(outbounds, detour)
	}
	group, err := NewLoadBalanceGroup(s.ctx, s.outbound, s.logger, outbounds, s.link, s.interval, s.idleTimeout, s.ttl, s.strategy)
	if err != nil {
		return err
	}
	s.group = group
	for _, providerTag := range s.providerTags {
		s.providers[providerTag].RegisterCallback(s.onProviderUpdated)
	}
	return nil
}

func (s *LoadBalance) PostStart() error {
	s.group.PostStart()
	return nil
}

func (s *LoadBalance) Close() error {
	return common.Close(
		common.PtrOrNil(s.group),
	)
}

func (s *LoadBalance) Now() string {
	return ""
}

func (s *LoadBalance) All() []string {
	var all []string
	for _, outbound := range s.group.loadOutbounds() {
		all = append(all, outbound.Tag())
	}
	return all
}

func (s *LoadBalance) SelectPreMatchOutbound(metadata *adapter.InboundContext, selectOutbound func(adapter.Outbound) (adapter.Outbound, adapter.PreMatchAction)) (adapter.Outbound, adapter.PreMatchAction) {
	s.group.Touch()
	var (
		preMatchOutbound adapter.Outbound
		preMatchAction   adapter.PreMatchAction
	)
	s.group.UnwrapPreMatch(metadata, func(outbound adapter.Outbound) bool {
		preMatchOutbound, preMatchAction = selectOutbound(outbound)
		return preMatchOutbound != nil
	})
	return preMatchOutbound, preMatchAction
}

func (s *LoadBalance) URLTest(ctx context.Context) (map[string]uint16, error) {
	return s.group.URLTest(ctx)
}

func (s *LoadBalance) CheckOutbounds() {
	s.group.CheckOutbounds(true)
}

func (s *LoadBalance) InterfaceUpdated(context.Context) {
	group := s.group
	if group == nil {
		return
	}
	if group.pause.IsDevicePaused() || group.pause.IsNetworkPaused() {
		return
	}
	go group.CheckOutbounds(true)
}

func (s *LoadBalance) isGroupActive() bool {
	if !s.group.started.Load() {
		return false
	}
	return time.Since(s.group.lastActive.Load()) <= s.group.idleTimeout
}

func (s *LoadBalance) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	s.group.Touch()
	metadata := adapter.ContextFrom(ctx)
	outbound := s.group.Unwrap(metadata, true)
	if outbound == nil || !common.Contains(outbound.Network(), network) {
		return nil, E.New("missing supported outbound")
	}
	if metadata != nil {
		metadata.AppendRealOutbound(outbound.Tag())
	}
	conn, err := outbound.DialContext(ctx, network, destination)
	if err == nil {
		return s.group.interruptGroup.NewConn(conn, interrupt.IsExternalConnectionFromContext(ctx), interrupt.IsProviderConnectionFromContext(ctx)), nil
	}
	s.logger.ErrorContext(ctx, err)
	go s.group.CheckOutbounds(true)
	return nil, err
}

func (s *LoadBalance) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	s.group.Touch()
	metadata := adapter.ContextFrom(ctx)
	outbound := s.group.Unwrap(metadata, true)
	if outbound == nil || !common.Contains(outbound.Network(), N.NetworkUDP) {
		return nil, E.New("missing supported outbound")
	}
	if metadata != nil {
		metadata.AppendRealOutbound(outbound.Tag())
	}
	conn, err := outbound.ListenPacket(ctx, destination)
	if err == nil {
		return s.group.interruptGroup.NewPacketConn(conn, interrupt.IsExternalConnectionFromContext(ctx), interrupt.IsProviderConnectionFromContext(ctx)), nil
	}
	s.logger.ErrorContext(ctx, err)
	go s.group.CheckOutbounds(true)
	return nil, err
}

func (s *LoadBalance) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	ctx = interrupt.ContextWithIsExternalConnection(ctx)
	s.connection.NewConnection(ctx, s, conn, metadata, onClose)
}

func (s *LoadBalance) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	ctx = interrupt.ContextWithIsExternalConnection(ctx)
	s.connection.NewPacketConnection(ctx, s, conn, metadata, onClose)
}

func (s *LoadBalance) onProviderUpdated(tag string) error {
	s.providerAccess.Lock()
	_, outbounds, outboundsCache, err := collectProviderOutbounds(
		tag,
		s.Dependencies(),
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
	s.outboundsCache = outboundsCache
	s.group.storeOutbounds(outbounds)
	s.providerAccess.Unlock()
	if s.isGroupActive() {
		s.group.access.Lock()
		if s.group.ticker != nil {
			s.group.ticker.Reset(s.group.interval)
		}
		s.group.access.Unlock()
		s.providerUpdateCheck.Schedule(func() {
			_, _ = s.group.urlTestWait(s.ctx, false)
		})
	}
	return nil
}

type outboundMatcher = func(outbound adapter.Outbound) bool

type strategyFn = func(metadata *adapter.InboundContext, touch bool, matcher outboundMatcher) adapter.Outbound

type LoadBalanceGroup struct {
	ctx context.Context
	// router                       adapter.Router
	outbound        adapter.OutboundManager
	pause           pause.Manager
	pauseCallback   *list.Element[pause.Callback]
	logger          log.Logger
	outbounds       []adapter.Outbound
	outboundsAccess sync.RWMutex
	link            string
	interval        time.Duration
	idleTimeout     time.Duration
	ttl             time.Duration
	history         *urltest.HistoryStorage
	checking        sync.Mutex
	fallbackIdx     atomic.Uint32
	fallbackAccess  sync.Mutex
	interruptGroup  *interrupt.Group
	access          sync.Mutex
	ticker          *time.Ticker
	close           chan struct{}
	started         atomic.Bool
	lastActive      common.TypedValue[time.Time]
	strategyFn      strategyFn
}

func NewLoadBalanceGroup(ctx context.Context, outboundManager adapter.OutboundManager, logger log.Logger, outbounds []adapter.Outbound, link string, interval time.Duration, idleTimeout time.Duration, ttl time.Duration, strategy string) (*LoadBalanceGroup, error) {
	if interval == 0 {
		interval = C.DefaultURLTestInterval
	}
	if idleTimeout == 0 {
		idleTimeout = C.DefaultURLTestIdleTimeout
	}
	if interval > idleTimeout {
		return nil, E.New("interval must be less or equal than idle_timeout")
	}
	if ttl == 0 {
		ttl = time.Minute * 10
	}
	history := service.PtrFromContext[urltest.HistoryStorage](ctx)
	if history == nil {
		return nil, E.New("missing URL test history storage")
	}
	if link == "" {
		link = "https://www.gstatic.com/generate_204"
	}
	loadBalanceGroup := &LoadBalanceGroup{
		ctx:            ctx,
		outbound:       outboundManager,
		logger:         logger,
		link:           link,
		interval:       interval,
		idleTimeout:    idleTimeout,
		ttl:            ttl,
		history:        history,
		close:          make(chan struct{}),
		pause:          service.FromContext[pause.Manager](ctx),
		interruptGroup: interrupt.NewGroup(),
	}
	loadBalanceGroup.storeOutbounds(outbounds)
	switch strategy {
	case StrategyRoundRobin:
		loadBalanceGroup.strategyFn = strategyRoundRobin(loadBalanceGroup, link)
	case StrategyConsistentHashing:
		loadBalanceGroup.strategyFn = strategyConsistentHashing(loadBalanceGroup, link)
	case StrategyStickySessions:
		loadBalanceGroup.strategyFn = strategyStickySessions(loadBalanceGroup, link)
	}
	return loadBalanceGroup, nil
}

func (g *LoadBalanceGroup) PostStart() {
	g.access.Lock()
	defer g.access.Unlock()
	g.started.Store(true)
	g.lastActive.Store(time.Now())
	go g.CheckOutbounds(false)
}

func (g *LoadBalanceGroup) Touch() {
	if !g.started.Load() {
		return
	}
	g.access.Lock()
	defer g.access.Unlock()
	if g.ticker != nil {
		g.lastActive.Store(time.Now())
		return
	}
	g.ticker = time.NewTicker(g.interval)
	go g.loopCheck()
	g.pauseCallback = pause.RegisterTicker(g.pause, g.ticker, g.interval, nil)
}

func (g *LoadBalanceGroup) Close() error {
	g.access.Lock()
	defer g.access.Unlock()
	if g.ticker == nil {
		return nil
	}
	g.ticker.Stop()
	g.pause.UnregisterCallback(g.pauseCallback)
	close(g.close)
	return nil
}

func (g *LoadBalanceGroup) loopCheck() {
	if time.Since(g.lastActive.Load()) > g.interval {
		g.lastActive.Store(time.Now())
		g.CheckOutbounds(false)
	}
	for {
		select {
		case <-g.close:
			return
		case <-g.ticker.C:
		}
		if time.Since(g.lastActive.Load()) > g.idleTimeout {
			g.access.Lock()
			g.ticker.Stop()
			g.ticker = nil
			g.pause.UnregisterCallback(g.pauseCallback)
			g.pauseCallback = nil
			g.access.Unlock()
			return
		}
		g.CheckOutbounds(false)
	}
}

func (g *LoadBalanceGroup) CheckOutbounds(force bool) {
	_, _ = g.urlTest(g.ctx, force)
}

func (g *LoadBalanceGroup) URLTest(ctx context.Context) (map[string]uint16, error) {
	return g.urlTest(ctx, true)
}

func (g *LoadBalanceGroup) urlTest(ctx context.Context, force bool) (map[string]uint16, error) {
	if !g.checking.TryLock() {
		return make(map[string]uint16), nil
	}
	defer g.checking.Unlock()
	return g.urlTestLocked(ctx, force)
}

func (g *LoadBalanceGroup) urlTestWait(ctx context.Context, force bool) (map[string]uint16, error) {
	g.checking.Lock()
	defer g.checking.Unlock()
	return g.urlTestLocked(ctx, force)
}

func (g *LoadBalanceGroup) urlTestLocked(ctx context.Context, force bool) (map[string]uint16, error) {
	return URLTestOutbounds(ctx, g.outbound, g.history, g.logger, g.loadOutbounds(), g.link, g.interval, force), nil
}

func (g *LoadBalanceGroup) Unwrap(metadata *adapter.InboundContext, touch bool) adapter.Outbound {
	return g.strategyFn(metadata, touch, nil)
}

func (g *LoadBalanceGroup) UnwrapPreMatch(metadata *adapter.InboundContext, matcher outboundMatcher) adapter.Outbound {
	return g.strategyFn(metadata, true, matcher)
}

func (g *LoadBalanceGroup) AliveForTestUrl(proxy adapter.Outbound) bool {
	return g.aliveForTestURL(proxy, make(map[string]bool))
}

func (g *LoadBalanceGroup) aliveForTestURL(proxy adapter.Outbound, checked map[string]bool) bool {
	if proxy == nil || checked[proxy.Tag()] {
		return false
	}
	checked[proxy.Tag()] = true
	if nested, isLoadBalance := proxy.(adapter.LoadBalanceGroup); isLoadBalance {
		for _, memberTag := range nested.All() {
			member, loaded := g.outbound.Outbound(memberTag)
			if loaded && g.aliveForTestURL(member, checked) {
				return true
			}
		}
		return false
	}
	return g.history.LoadURLTestHistory(RealTag(g.outbound, proxy)) != nil
}

func (g *LoadBalanceGroup) nextFallback(outbounds []adapter.Outbound, touch bool, matcher outboundMatcher) adapter.Outbound {
	g.fallbackAccess.Lock()
	defer g.fallbackAccess.Unlock()
	length := len(outbounds)
	if length == 0 {
		return nil
	}
	nextIndex := g.fallbackIdx.Load() + 1
	outbound := outbounds[int(nextIndex)%length]
	if matcher != nil && !matcher(outbound) {
		return nil
	}
	if matcher == nil || touch {
		g.fallbackIdx.Store(nextIndex)
	}
	return outbound
}

func (g *LoadBalanceGroup) loadOutbounds() []adapter.Outbound {
	g.outboundsAccess.RLock()
	defer g.outboundsAccess.RUnlock()
	return g.outbounds
}

func (g *LoadBalanceGroup) storeOutbounds(outbounds []adapter.Outbound) {
	g.outboundsAccess.Lock()
	g.outbounds = outbounds
	g.outboundsAccess.Unlock()
}

func getKey(metadata *adapter.InboundContext) string {
	if metadata == nil {
		return ""
	}

	var metadataHost string
	if metadata.Destination.IsDomain() {
		metadataHost = metadata.Destination.Fqdn
	} else if metadata.SniffHost != "" {
		metadataHost = metadata.SniffHost
	} else {
		metadataHost = metadata.Domain
	}

	if metadataHost != "" {
		// ip host
		if ip := net.ParseIP(metadataHost); ip != nil {
			return metadataHost
		}

		if etld, err := publicsuffix.EffectiveTLDPlusOne(metadataHost); err == nil {
			return etld
		}
	}

	var destinationAddr netip.Addr
	if len(metadata.DestinationAddresses) > 0 {
		destinationAddr = metadata.DestinationAddresses[0]
	} else {
		destinationAddr = metadata.Destination.Addr
	}

	if !destinationAddr.IsValid() {
		return ""
	}

	return destinationAddr.String()
}

func getKeyWithSrcAndDst(metadata *adapter.InboundContext) string {
	dst := getKey(metadata)
	src := ""
	if metadata != nil {
		src = metadata.Source.Addr.String()
	}

	return fmt.Sprintf("%s%s", src, dst)
}

func jumpHash(key uint64, buckets int32) int32 {
	var b, j int64

	for j < int64(buckets) {
		b = j
		key = key*2862933555777941757 + 1
		j = int64(float64(b+1) * (float64(int64(1)<<31) / float64((key>>33)+1)))
	}

	return int32(b)
}

func strategyRoundRobin(g *LoadBalanceGroup, url string) strategyFn {
	idx := 0
	idxMutex := sync.Mutex{}
	return func(metadata *adapter.InboundContext, touch bool, matcher outboundMatcher) adapter.Outbound {
		idxMutex.Lock()
		defer idxMutex.Unlock()

		outbounds := g.loadOutbounds()
		i := 0
		length := len(outbounds)

		for ; i < length; i++ {
			id := (idx + i) % length
			proxy := outbounds[id]
			if g.AliveForTestUrl(proxy) {
				i++
				if matcher != nil && !matcher(proxy) {
					return nil
				}
				if touch {
					idx = (idx + i) % length
				}
				return proxy
			}
		}

		return g.nextFallback(outbounds, touch, matcher)
	}
}

func strategyConsistentHashing(g *LoadBalanceGroup, url string) strategyFn {
	maxRetry := 5
	hash := maphash.NewHasher[string]()
	return func(metadata *adapter.InboundContext, touch bool, matcher outboundMatcher) adapter.Outbound {
		outbounds := g.loadOutbounds()
		key := hash.Hash(getKey(metadata))
		buckets := int32(len(outbounds))
		for i := 0; i < maxRetry; i, key = i+1, key+1 {
			idx := jumpHash(key, buckets)
			proxy := outbounds[idx]
			if g.AliveForTestUrl(proxy) {
				if matcher != nil && !matcher(proxy) {
					return nil
				}
				return proxy
			}
		}

		// when availability is poor, traverse the entire list to get the available nodes
		for _, proxy := range outbounds {
			if g.AliveForTestUrl(proxy) {
				if matcher != nil && !matcher(proxy) {
					return nil
				}
				return proxy
			}
		}

		return g.nextFallback(outbounds, touch, matcher)
	}
}

func strategyStickySessions(g *LoadBalanceGroup, url string) strategyFn {
	return strategyStickySessionsWithIndex(g, func(key uint64, length int) int {
		return int(jumpHash(key+uint64(time.Now().UnixNano()), int32(length)))
	})
}

func strategyStickySessionsWithIndex(g *LoadBalanceGroup, selectIndex func(key uint64, length int) int) strategyFn {
	maxRetry := 5
	lruCache := common.Must1(freelru.New[uint64, int](1000, maphash.NewHasher[uint64]().Hash32, true))
	lruCache.SetLifetime(g.ttl)
	hash := maphash.NewHasher[string]()
	return func(metadata *adapter.InboundContext, touch bool, matcher outboundMatcher) adapter.Outbound {
		outbounds := g.loadOutbounds()
		key := hash.Hash(getKeyWithSrcAndDst(metadata))
		length := len(outbounds)
		var (
			idx int
			has bool
		)
		if matcher == nil {
			idx, has = lruCache.Get(key)
		} else {
			idx, has = lruCache.Peek(key)
		}
		validMapping := has && idx < length
		if !validMapping {
			idx = selectIndex(key, length)
		}

		nowIdx := idx
		for i := 1; i < maxRetry; i++ {
			proxy := outbounds[nowIdx]
			if g.AliveForTestUrl(proxy) {
				matched := matcher == nil || matcher(proxy)
				if !validMapping || nowIdx != idx {
					lruCache.Add(key, nowIdx)
				} else if matcher != nil {
					lruCache.Get(key)
				}
				if !matched {
					return nil
				}
				return proxy
			} else {
				nowIdx = selectIndex(key, length)
			}
		}
		fbIdx := int(jumpHash(key, int32(length)))
		matched := matcher == nil || matcher(outbounds[fbIdx])
		lruCache.Add(key, fbIdx)
		if !matched {
			return nil
		}
		return outbounds[fbIdx]
	}
}
