package local

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/sagernet/fswatch"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/provider"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/provider/parser"
	"github.com/sagernet/sing/common/batch"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/filemanager"
)

func RegisterProvider(registry *provider.Registry) {
	provider.Register[option.ProviderLocalOptions](registry, C.ProviderTypeLocal, NewProviderLocal)
}

var (
	_ adapter.Provider = (*ProviderLocal)(nil)
	_ adapter.Service  = (*ProviderLocal)(nil)
)

// ProviderLocal is a local outbounds provider.
type ProviderLocal struct {
	callbacks          list.List[adapter.ProviderUpdateCallback]
	callbackAccess     sync.Mutex
	cancel             context.CancelFunc
	ctx                context.Context
	healchcheckHistory adapter.URLTestHistoryStorage
	logger             log.ContextLogger
	logFactory         log.Factory
	outbound           adapter.OutboundManager
	outbounds          []adapter.Outbound
	outboundsByTag     map[string]adapter.Outbound
	parentCtx          context.Context
	path               string
	router             adapter.Router
	tag                string
	watcher            *fswatch.Watcher
}

func NewProviderLocal(ctx context.Context, router adapter.Router, logFactory log.Factory, tag string, options option.ProviderLocalOptions) (adapter.Provider, error) {
	if tag == "" {
		return nil, E.New("provider tag is required")
	}
	if options.Path == "" {
		return nil, E.New("provider path is required")
	}
	logger := logFactory.NewLogger(F.ToString("provider/local", "[", tag, "]"))
	provider := &ProviderLocal{
		ctx:            ctx,
		logFactory:     logFactory,
		logger:         logger,
		outbound:       service.FromContext[adapter.OutboundManager](ctx),
		outboundsByTag: make(map[string]adapter.Outbound),
		parentCtx:      ctx,
		path:           options.Path,
		router:         router,
		tag:            tag,
	}
	filePath := filemanager.BasePath(ctx, options.Path)
	filePath, _ = filepath.Abs(filePath)
	watcher, err := fswatch.NewWatcher(fswatch.Options{
		Path: []string{filePath},
		Callback: func(path string) {
			uErr := provider.reloadFile(path)
			if uErr != nil {
				logger.Error(E.Cause(uErr, "reload provider ", tag))
			}
		},
	})
	if err != nil {
		return nil, err
	}
	provider.watcher = watcher
	return provider, nil
}

// Close implements adapter.Service.
func (s *ProviderLocal) Close() error {
	if s.cancel != nil {
		s.cancel()
	}
	var err error
	for _, ob := range s.outbounds {
		if err2 := s.outbound.Remove(ob.Tag()); err2 != nil {
			err = E.Append(err, err2, func(err error) error {
				return E.Cause(err, "close outbound [", ob.Tag(), "]")
			})
		}
	}
	s.outbounds = nil
	s.outboundsByTag = nil
	return err
}

// Start implements adapter.Service.
func (s *ProviderLocal) Start() error {
	if s.cancel != nil {
		return nil
	}
	s.ctx, s.cancel = context.WithCancel(s.ctx)
	s.healchcheckHistory = service.FromContext[adapter.URLTestHistoryStorage](s.ctx)
	if s.healchcheckHistory == nil {
		if clashServer := service.FromContext[adapter.ClashServer](s.ctx); clashServer != nil {
			s.healchcheckHistory = clashServer.HistoryStorage()
		} else {
			s.healchcheckHistory = urltest.NewHistoryStorage()
		}
	}
	err := s.reloadFile(s.path)
	if err != nil {
		return err
	}
	if s.watcher != nil {
		err := s.watcher.Start()
		if err != nil {
			s.logger.Error(E.Cause(err, "watch provider file"))
		}

	}
	return nil
}

// Outbound implements adapter.Provider.
func (s *ProviderLocal) Outbound(tag string) (adapter.Outbound, bool) {
	outbound, loaded := s.outboundsByTag[tag]
	return outbound, loaded
}

// Outbounds implements adapter.Provider.
func (s *ProviderLocal) Outbounds() []adapter.Outbound {
	return s.outbounds
}

// RegisterCallback implements adapter.Provider.
func (s *ProviderLocal) RegisterCallback(callback adapter.ProviderUpdateCallback) *list.Element[adapter.ProviderUpdateCallback] {
	s.callbackAccess.Lock()
	defer s.callbackAccess.Unlock()
	return s.callbacks.PushBack(callback)
}

// Tag implements adapter.Provider.
func (s *ProviderLocal) Tag() string {
	return s.tag
}

// Type implements adapter.Provider.
func (s *ProviderLocal) Type() string {
	return C.ProviderTypeLocal
}

// UnregisterCallback implements adapter.Provider.
func (s *ProviderLocal) UnregisterCallback(element *list.Element[adapter.ProviderUpdateCallback]) {
	s.callbackAccess.Lock()
	defer s.callbackAccess.Unlock()
	s.callbacks.Remove(element)
}

func (s *ProviderLocal) createOutbounds(opts []option.Outbound) {
	s.removeUseless(opts)
	outbounds := make([]adapter.Outbound, 0, len(opts))
	outboundsByTag := make(map[string]adapter.Outbound)
	for _, opt := range opts {
		tag := s.tag + "/" + opt.Tag
		err := s.outbound.Create(
			s.parentCtx,
			s.router,
			s.logFactory.NewLogger(F.ToString("provider/", opt.Type, "[", tag, "]")),
			tag,
			opt.Type,
			opt.Options,
		)
		if err != nil {
			s.logger.Warn("create [", tag, "]: ", err)
			continue
		}
		outbound, loaded := s.outbound.Outbound(tag)
		if !loaded {
			s.logger.Warn("outbound [", tag, "] not found")
			continue
		}
		outbounds = append(outbounds, outbound)
		outboundsByTag[tag] = outbound
	}
	s.outbounds = outbounds
	s.outboundsByTag = outboundsByTag
}

func (s *ProviderLocal) reloadFile(path string) error {
	content, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	outbounds, err := parser.ParseSubscription(s.ctx, string(content))
	if err != nil {
		return err
	}
	s.createOutbounds(outbounds)
	s.callbackAccess.Lock()
	callbacks := s.callbacks.Array()
	s.callbackAccess.Unlock()
	for _, callback := range callbacks {
		callback(s.tag, s.outbounds)
	}
	s.healthcheck(s.ctx)
	return nil
}

func (s *ProviderLocal) removeUseless(outbounds []option.Outbound) {
	outsByTag := make(map[string]bool)
	for _, outbound := range outbounds {
		outsByTag[s.Tag()+"/"+outbound.Tag] = true
	}
	for _, outbound := range s.outbounds {
		if !outsByTag[outbound.Tag()] {
			err := s.outbound.Remove(outbound.Tag())
			if err != nil {
				s.logger.Error(err, "remove outbound [", outbound.Tag(), "]")
			}
		}
	}
}

func (s *ProviderLocal) healthcheck(ctx context.Context) {
	b, _ := batch.New(ctx, batch.WithConcurrencyNum[any](10))
	for _, detour := range s.outbounds {
		tag := detour.Tag()
		detour, loaded := s.outbound.Outbound(tag)
		if !loaded {
			continue
		}
		b.Go(tag, func() (any, error) {
			ctx, cancel := context.WithTimeout(ctx, C.TCPTimeout)
			defer cancel()
			t, err := urltest.URLTest(ctx, "", detour)
			if err != nil {
				s.logger.DebugContext(ctx, "outbound ", tag, " unavailable: ", err)
				s.healchcheckHistory.DeleteURLTestHistory(tag)
			} else {
				s.logger.DebugContext(ctx, "outbound ", tag, " available: ", t, "ms")
				s.healchcheckHistory.StoreURLTestHistory(tag, &adapter.URLTestHistory{
					Time:  time.Now(),
					Delay: t,
				})
			}
			return nil, nil
		})
	}
}
