package provider

import (
	"context"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/batch"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"
)

var _ adapter.InterfaceUpdateListener = (*Adapter)(nil)

type Adapter struct {
	ctx            context.Context
	outbound       adapter.OutboundManager
	pauseManager   pause.Manager
	router         adapter.Router
	logFactory     log.Factory
	logger         log.ContextLogger
	providerType   string
	providerTag    string
	outbounds      []adapter.Outbound
	outboundsByTag map[string]adapter.Outbound
	ticker         *time.Ticker
	checking       atomic.Bool
	history        adapter.URLTestHistoryStorage
	callbackAccess sync.Mutex
	callbacks      list.List[adapter.ProviderUpdateCallback]

	link     string
	enabled  bool
	timeout  time.Duration
	interval time.Duration
}

func NewAdapter(ctx context.Context, router adapter.Router, outbound adapter.OutboundManager, pauseManager pause.Manager, logFactory log.Factory, logger log.ContextLogger, providerTag string, providerType string, options option.ProviderHealthCheckOptions) Adapter {
	timeout := time.Duration(options.Timeout)
	if timeout == 0 {
		timeout = 3 * time.Second
	}
	interval := time.Duration(options.Interval)
	if interval == 0 {
		interval = 10 * time.Minute
	}
	if interval < time.Minute {
		interval = time.Minute
	}
	return Adapter{
		ctx:          ctx,
		outbound:     outbound,
		pauseManager: pauseManager,
		router:       router,
		logFactory:   logFactory,
		logger:       logger,
		providerType: providerType,
		providerTag:  providerTag,

		link:     options.URL,
		enabled:  options.Enabled,
		timeout:  timeout,
		interval: interval,
	}
}

func (a *Adapter) PostStart() error {
	a.history = service.FromContext[adapter.URLTestHistoryStorage](a.ctx)
	if a.history == nil {
		if clashServer := service.FromContext[adapter.ClashServer](a.ctx); clashServer != nil {
			a.history = clashServer.HistoryStorage()
		} else {
			a.history = urltest.NewHistoryStorage()
		}
	}
	go a.loopCheck()
	return nil
}

func (a *Adapter) Type() string {
	return a.providerType
}

func (a *Adapter) Tag() string {
	return a.providerTag
}

func (a *Adapter) Outbounds() []adapter.Outbound {
	return a.outbounds
}

func (a *Adapter) Outbound(tag string) (adapter.Outbound, bool) {
	if a.outboundsByTag == nil {
		return nil, false
	}
	detour, ok := a.outboundsByTag[tag]
	return detour, ok
}

func (a *Adapter) UpdateOutbounds(oldOpts []option.Outbound, newOpts []option.Outbound) {
	a.removeUseless(oldOpts, newOpts)
	var (
		oldOptByTag    = make(map[string]option.Outbound)
		outbounds      = make([]adapter.Outbound, 0, len(newOpts))
		outboundsByTag = make(map[string]adapter.Outbound)
	)
	for _, opt := range oldOpts {
		oldOptByTag[opt.Tag] = opt
	}
	for i, opt := range newOpts {
		oldOpt, exist := oldOptByTag[opt.Tag]
		var tag string
		if opt.Tag != "" {
			tag = F.ToString(a.providerTag, "/", opt.Tag)
		} else {
			tag = F.ToString(a.providerTag, "/", i)
		}
		if !exist || !reflect.DeepEqual(opt, oldOpt) {
			err := a.outbound.Create(
				adapter.WithContext(a.ctx, &adapter.InboundContext{
					Outbound: tag,
				}),
				a.router,
				a.logFactory.NewLogger(F.ToString("outbound/", opt.Type, "[", tag, "]")),
				tag,
				opt.Type,
				opt.Options,
			)
			if err != nil {
				a.logger.Warn(err)
				continue
			}
		}
		outbound, _ := a.outbound.Outbound(tag)
		outbounds = append(outbounds, outbound)
		outboundsByTag[tag] = outbound
	}
	if a.enabled && a.history != nil {
		go a.HealthCheck()
	}
	a.outbounds = outbounds
	a.outboundsByTag = outboundsByTag
}

func (a *Adapter) HealthCheck() (map[string]uint16, error) {
	if a.ticker != nil {
		a.ticker.Reset(a.interval)
	}
	return a.healthcheck()
}

func (s *Adapter) RegisterCallback(callback adapter.ProviderUpdateCallback) *list.Element[adapter.ProviderUpdateCallback] {
	s.callbackAccess.Lock()
	defer s.callbackAccess.Unlock()
	return s.callbacks.PushBack(callback)
}

func (s *Adapter) UnregisterCallback(element *list.Element[adapter.ProviderUpdateCallback]) {
	s.callbackAccess.Lock()
	defer s.callbackAccess.Unlock()
	s.callbacks.Remove(element)
}

func (a *Adapter) UpdateGroups() {
	for element := a.callbacks.Front(); element != nil; element = element.Next() {
		err := element.Value(a.providerTag)
		if err != nil {
			a.logger.Error("update group ", err)
		}
	}
}

func (a *Adapter) InterfaceUpdated() {
	if !a.enabled && a.history == nil {
		return
	}
	go a.HealthCheck()
}

func (a *Adapter) Close() error {
	if a.ticker != nil {
		a.ticker.Stop()
	}
	outbounds := a.outbounds
	a.outbounds = nil
	var err error
	for _, ob := range outbounds {
		if err2 := a.outbound.Remove(ob.Tag()); err2 != nil {
			err = E.Append(err, err2, func(err error) error {
				return E.Cause(err, "close outbound [", ob.Tag(), "]")
			})
		}
	}
	return err
}

func (a *Adapter) loopCheck() {
	if !a.enabled {
		return
	}
	a.ticker = time.NewTicker(a.interval)
	a.healthcheck()
	for {
		select {
		case <-a.ctx.Done():
			return
		case <-a.ticker.C:
			a.pauseManager.WaitActive()
			a.healthcheck()
		}
	}
}

func (a *Adapter) healthcheck() (map[string]uint16, error) {
	result := make(map[string]uint16)
	if a.checking.Swap(true) {
		return result, nil
	}
	defer a.checking.Store(false)
	b, _ := batch.New(a.ctx, batch.WithConcurrencyNum[any](10))
	var resultAccess sync.Mutex
	checked := make(map[string]bool)
	for _, detour := range a.outbounds {
		tag := detour.Tag()
		if checked[tag] {
			continue
		}
		checked[tag] = true
		b.Go(tag, func() (any, error) {
			ctx, cancel := context.WithTimeout(a.ctx, a.timeout)
			defer cancel()
			t, err := urltest.URLTest(ctx, a.link, detour)
			if err != nil {
				a.logger.Debug("outbound ", tag, " unavailable: ", err)
				a.history.DeleteURLTestHistory(tag)
			} else {
				a.logger.Debug("outbound ", tag, " available: ", t, "ms")
				a.history.StoreURLTestHistory(tag, &adapter.URLTestHistory{
					Time:  time.Now(),
					Delay: t,
				})
				resultAccess.Lock()
				result[tag] = t
				resultAccess.Unlock()
			}
			return nil, nil
		})
	}
	b.Wait()
	return result, nil
}

func (a *Adapter) removeUseless(oldOpts []option.Outbound, newOpts []option.Outbound) {
	if len(oldOpts) == 0 {
		return
	}
	exists := make(map[string]bool)
	for _, opt := range newOpts {
		exists[opt.Tag] = true
	}
	for i, opt := range oldOpts {
		if !exists[opt.Tag] {
			var tag string
			if opt.Tag != "" {
				tag = F.ToString(a.providerTag, "/", opt.Tag)
			} else {
				tag = F.ToString(a.providerTag, "/", i)
			}
			if err := a.outbound.Remove(tag); err != nil {
				a.logger.Error(err, "close outbound [", tag, "]")
			}
		}
	}
}
