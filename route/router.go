package route

import (
	"context"
	"os"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/expiringmap"
	"github.com/sagernet/sing-box/common/process"
	"github.com/sagernet/sing-box/common/taskmonitor"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	R "github.com/sagernet/sing-box/route/rule"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/task"
	"github.com/sagernet/sing/contrab/freelru"
	"github.com/sagernet/sing/contrab/maphash"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"
)

var _ adapter.Router = (*Router)(nil)

type Router struct {
	ctx                          context.Context
	logger                       log.ContextLogger
	inbound                      adapter.InboundManager
	outbound                     adapter.OutboundManager
	provider                     adapter.ProviderManager
	dns                          adapter.DNSRouter
	dnsTransport                 adapter.DNSTransportManager
	connection                   adapter.ConnectionManager
	network                      adapter.NetworkManager
	httpClientManager            adapter.HTTPClientManager
	rules                        []adapter.Rule
	needFindProcess              bool
	ruleSetNeedFindProcess       atomic.Bool
	ruleSetNeedFindProcessAccess sync.Mutex
	hasUpdatableRuleSet          bool
	needFindNeighbor             bool
	leaseFiles                   []string
	ruleSets                     []adapter.RuleSet
	ruleSetMap                   map[string]adapter.RuleSet
	ruleSetUpdater               *R.RuleSetUpdater
	processSearcher              process.Searcher
	processCache                 *freelru.Cache[processCacheKey, processCacheEntry]
	neighborResolver             adapter.NeighborResolver
	pauseManager                 pause.Manager
	trackers                     []adapter.ConnectionTracker
	platformInterface            adapter.PlatformInterface

	quicSniffCache             *expiringmap.Map[quicSniffCacheKey, quicSniffResult]
	defaultDomainMatchStrategy C.DomainMatchStrategy
	reloadChan                 chan<- struct{}
}

func NewRouter(ctx context.Context, logFactory log.Factory, options option.RouteOptions, dnsOptions option.DNSOptions, reloadChan chan<- struct{}) *Router {
	platformInterface := service.FromContext[adapter.PlatformInterface](ctx)
	return &Router{
		ctx:               ctx,
		logger:            logFactory.NewLogger("router"),
		inbound:           service.FromContext[adapter.InboundManager](ctx),
		outbound:          service.FromContext[adapter.OutboundManager](ctx),
		provider:          service.FromContext[adapter.ProviderManager](ctx),
		dns:               service.FromContext[adapter.DNSRouter](ctx),
		dnsTransport:      service.FromContext[adapter.DNSTransportManager](ctx),
		connection:        service.FromContext[adapter.ConnectionManager](ctx),
		network:           service.FromContext[adapter.NetworkManager](ctx),
		httpClientManager: service.FromContext[adapter.HTTPClientManager](ctx),
		rules:             make([]adapter.Rule, 0, len(options.Rules)),
		ruleSetMap:        make(map[string]adapter.RuleSet),
		needFindProcess:   hasRule(options.Rules, isProcessRule) || hasDNSRule(dnsOptions.Rules, isProcessDNSRule) || options.FindProcess || C.IsAndroid && platformInterface != nil,
		needFindNeighbor:  hasRule(options.Rules, isNeighborRule) || hasDNSRule(dnsOptions.Rules, isNeighborDNSRule) || hasLocalNeighborDNSServer(dnsOptions.Servers) || options.FindNeighbor,
		leaseFiles:        options.DHCPLeaseFiles,
		pauseManager:      service.FromContext[pause.Manager](ctx),
		platformInterface: platformInterface,

		defaultDomainMatchStrategy: C.DomainMatchStrategy(options.DefaultDomainMatchStrategy),
		reloadChan:                 reloadChan,
	}
}

func (r *Router) Initialize(rules []option.Rule, ruleSets []option.RuleSet) error {
	if r.defaultDomainMatchStrategy == C.DomainMatchStrategyFQDNOnly || r.defaultDomainMatchStrategy == C.DomainMatchStrategySniffHostOnly {
		return E.New("default_domain_match_strategy cannot be fqdn_only or sniffhost_only")
	}
	for i, options := range rules {
		err := R.ValidateNoNestedRuleActions(options)
		if err != nil {
			return E.Cause(err, "parse rule[", i, "]")
		}
		rule, err := R.NewRule(r.ctx, r.logger, options, true)
		if err != nil {
			return E.Cause(err, "parse rule[", i, "]")
		}
		r.rules = append(r.rules, rule)
	}
	for i, options := range ruleSets {
		for _, tag := range options.Tag {
			if _, exists := r.ruleSetMap[tag]; exists {
				return E.New("duplicate rule-set tag: ", tag)
			}
			ruleSet, err := R.NewRuleSet(r.ctx, r.logger, tag, options)
			if err != nil {
				return E.Cause(err, "parse rule-set[", i, "]")
			}
			r.ruleSets = append(r.ruleSets, ruleSet)
			r.ruleSetMap[tag] = ruleSet
			if options.Type != C.RuleSetTypeInline {
				r.hasUpdatableRuleSet = true
			}
		}
	}
	return nil
}

func (r *Router) ValidateRuleActions() error {
	return r.validateRuleActions(true)
}

func (r *Router) ValidateDeferredRuleActions() error {
	return r.validateRuleActions(false)
}

func (r *Router) validateRuleActions(deferDynamicProviders bool) error {
	for i, rule := range r.rules {
		var outboundTag, serverTag string
		switch action := rule.Action().(type) {
		case *R.RuleActionRoute:
			outboundTag = action.Outbound
		case *R.RuleActionBypass:
			outboundTag = action.Outbound
		case *R.RuleActionResolve:
			serverTag = action.Server
		}
		if outboundTag != "" {
			if _, loaded := r.outbound.Outbound(outboundTag); !loaded {
				if !deferDynamicProviders || !r.isDeferredProviderOutbound(outboundTag) {
					return E.New("rule[", i, "]: outbound not found: ", outboundTag)
				}
			}
		}
		if serverTag != "" {
			if _, loaded := r.dnsTransport.Transport(serverTag); !loaded {
				return E.New("rule[", i, "]: DNS server not found: ", serverTag)
			}
		}
	}
	return nil
}

func (r *Router) isDeferredProviderOutbound(tag string) bool {
	if r.provider == nil {
		return false
	}
	for _, provider := range r.provider.Providers() {
		switch provider.Type() {
		case C.ProviderTypeLocal, C.ProviderTypeRemote:
			prefix := provider.Tag() + "/"
			if strings.HasPrefix(tag, prefix) && len(tag) > len(prefix) {
				return true
			}
		}
	}
	return false
}

func (r *Router) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	monitor := taskmonitor.New(r.logger, C.StartTimeout)
	switch stage {
	case adapter.StartStateInitialize:
		r.quicSniffCache = expiringmap.New[quicSniffCacheKey, quicSniffResult](quicSniffCacheTTL)
		scope.Add(func() error {
			r.quicSniffCache.Close()
			return nil
		})
		for _, ruleSet := range r.ruleSets {
			scope.Add(ruleSet.Close)
		}
		if r.needFindNeighbor {
			if r.platformInterface != nil && r.platformInterface.UsePlatformNeighborResolver() {
				monitor.Start("initialize neighbor resolver")
				resolver := newPlatformNeighborResolver(r.logger, r.platformInterface)
				err := resolver.Start()
				monitor.Finish()
				if err != nil {
					r.logger.Error(E.Cause(err, "start neighbor resolver"))
				} else {
					r.neighborResolver = resolver
					scope.Add(resolver.Close)
				}
			} else {
				monitor.Start("initialize neighbor resolver")
				resolver, err := newNeighborResolver(r.logger, r.leaseFiles)
				monitor.Finish()
				if err != nil {
					if err != os.ErrInvalid {
						r.logger.Error(E.Cause(err, "create neighbor resolver"))
					}
				} else {
					err = resolver.Start()
					if err != nil {
						r.logger.Error(E.Cause(err, "start neighbor resolver"))
					} else {
						r.neighborResolver = resolver
						scope.Add(resolver.Close)
					}
				}
			}
		}
	case adapter.StartStateStart:
		var startContext *adapter.HTTPStartContext
		if len(r.ruleSets) > 0 {
			monitor.Start("initialize rule-set")
			startContext = adapter.NewHTTPStartContext()
			var ruleSetStartGroup task.Group
			for i, ruleSet := range r.ruleSets {
				ruleSetInPlace := ruleSet
				ruleSetStartGroup.Append0(func(ctx context.Context) error {
					err := ruleSetInPlace.StartContext(ctx, startContext)
					if err != nil {
						return E.Cause(err, "initialize rule-set[", i, "]")
					}
					return nil
				})
			}
			ruleSetStartGroup.Concurrency(5)
			ruleSetStartGroup.FastFail()
			err := ruleSetStartGroup.Run(r.ctx)
			monitor.Finish()
			if err != nil {
				return err
			}
		}
		if startContext != nil {
			startContext.Close()
		}
		r.ruleSetUpdater = R.NewRuleSetUpdater(r.ctx, r.ruleSets)
		if r.ruleSetUpdater != nil {
			scope.Add(r.ruleSetUpdater.Close)
		}
		r.network.Initialize(r.ruleSets)
		for _, ruleSet := range r.ruleSets {
			ruleSet.RegisterCallback(func(adapter.RuleSet) {
				r.updateRuleSetNeedFindProcess()
			})
		}
		r.updateRuleSetNeedFindProcess()
		if r.NeedFindProcess() || r.hasUpdatableRuleSet {
			if r.platformInterface != nil && r.platformInterface.UsePlatformConnectionOwnerFinder() {
				r.processSearcher = newPlatformSearcher(r.platformInterface)
			} else {
				monitor.Start("initialize process searcher")
				searcher, err := process.NewSearcher(process.Config{
					Logger:         r.logger,
					PackageManager: r.network.PackageManager(),
				})
				monitor.Finish()
				if err != nil {
					if err != os.ErrInvalid {
						r.logger.Warn(E.Cause(err, "create process searcher"))
					}
				} else {
					r.processSearcher = searcher
				}
			}
		}
		if r.processSearcher != nil {
			scope.Add(r.processSearcher.Close)
			processCache := common.Must1(freelru.New[processCacheKey, processCacheEntry](256, maphash.NewHasher[processCacheKey]().Hash32, true))
			processCache.SetLifetime(200 * time.Millisecond)
			r.processCache = processCache
		}
		for i, rule := range r.rules {
			scope.Add(rule.Close)
			monitor.Start("initialize rule[", i, "]")
			err := rule.Start()
			monitor.Finish()
			if err != nil {
				return E.Cause(err, "initialize rule[", i, "]")
			}
		}
	case adapter.StartStatePostStart:
		if r.ruleSetUpdater != nil {
			r.ruleSetUpdater.Start()
		}
		return nil
	case adapter.StartStateStarted:
		for _, ruleSet := range r.ruleSets {
			ruleSet.Cleanup()
		}
		runtime.GC()
	}
	return nil
}

func (r *Router) RuleSet(tag string) (adapter.RuleSet, bool) {
	ruleSet, loaded := r.ruleSetMap[tag]
	return ruleSet, loaded
}

func (r *Router) Rules() []adapter.Rule {
	return r.rules
}

func (r *Router) AppendTracker(tracker adapter.ConnectionTracker) {
	r.trackers = append(r.trackers, tracker)
}

func (r *Router) NeedFindProcess() bool {
	return r.needFindProcess || r.ruleSetNeedFindProcess.Load()
}

func (r *Router) updateRuleSetNeedFindProcess() {
	r.ruleSetNeedFindProcessAccess.Lock()
	defer r.ruleSetNeedFindProcessAccess.Unlock()
	r.ruleSetNeedFindProcess.Store(slices.ContainsFunc(r.ruleSets, func(ruleSet adapter.RuleSet) bool {
		return ruleSet.Metadata().ContainsProcessRule
	}))
}

func (r *Router) NeedFindNeighbor() bool {
	return r.needFindNeighbor
}

func (r *Router) NeighborResolver() adapter.NeighborResolver {
	return r.neighborResolver
}

func (r *Router) ResetNetwork() {
	r.httpClientManager.ResetNetwork()
	r.dns.ResetNetwork()
	if r.processCache != nil {
		r.processCache.Purge()
	}
	if r.processSearcher != nil {
		r.processSearcher.ResetCache()
	}
}

const quicSniffCacheTTL = 5 * time.Minute

func (r *Router) processQUICSniff(ctx context.Context, metadata *adapter.InboundContext) {
	if metadata.Protocol != C.ProtocolQUIC {
		return
	}
	metadata.SniffDestination = metadata.Destination
	if metadata.SniffHost != "" {
		r.cacheQUICSniff(metadata.Source, metadata.SniffDestination, quicSniffResult{
			host: metadata.SniffHost, hasECHExtension: metadata.SniffHasECHExtension,
		})
	} else if result, loaded := r.lookupQUICSniff(metadata.Source, metadata.SniffDestination); loaded {
		metadata.SniffHost = result.host
		metadata.SniffHasECHExtension = result.hasECHExtension
		r.logger.DebugContext(ctx, "restored QUIC SNI from cache: ", result.host)
	}
}

type quicSniffCacheKey struct {
	source      M.Socksaddr
	destination M.Socksaddr
}

type quicSniffResult struct {
	host            string
	hasECHExtension bool
}

func (r *Router) cacheQUICSniff(source, destination M.Socksaddr, result quicSniffResult) {
	r.quicSniffCache.Store(quicSniffCacheKey{source, destination}, result)
}

func (r *Router) lookupQUICSniff(source, destination M.Socksaddr) (quicSniffResult, bool) {
	return r.quicSniffCache.LoadAndRefresh(quicSniffCacheKey{source, destination})
}

func (r *Router) refreshQUICSniff(source, destination M.Socksaddr, result quicSniffResult) {
	r.quicSniffCache.StoreIf(quicSniffCacheKey{source, destination}, result, func(current quicSniffResult, loaded bool) bool {
		return !loaded || current == result
	})
}

func (r *Router) DefaultDomainMatchStrategy() C.DomainMatchStrategy {
	return r.defaultDomainMatchStrategy
}

func (r *Router) Reload() {
	if r.platformInterface == nil {
		select {
		case r.reloadChan <- struct{}{}:
		default:
		}
	}
}
