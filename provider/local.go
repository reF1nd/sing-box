package provider

import (
	"context"
	"os"
	"runtime"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/rw"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"
)

var (
	_ adapter.OutboundProvider        = (*LocalProvider)(nil)
	_ adapter.InterfaceUpdateListener = (*LocalProvider)(nil)
)

type LocalProvider struct {
	myProviderAdapter
}

func NewLocalProvider(ctx context.Context, router adapter.Router, logger log.ContextLogger, options option.OutboundProvider, path string) (*LocalProvider, error) {
	interval := time.Duration(options.HealthcheckInterval)
	if interval == 0 {
		interval = C.DefaultURLTestInterval
	}
	ctx, cancel := context.WithCancel(ctx)
	provider := &LocalProvider{
		myProviderAdapter: myProviderAdapter{
			ctx:                 ctx,
			cancel:              cancel,
			router:              router,
			logger:              logger,
			tag:                 options.Tag,
			path:                path,
			healthcheckUrl:      options.HealthcheckUrl,
			healthcheckInterval: interval,
			overrideDialer:      options.OverrideDialer,
			includes:            options.Includes,
			excludes:            options.Excludes,
			types:               options.Types,
			ports:               make(map[int]bool),
			providerType:        C.TypeLocalProvider,
			close:               make(chan struct{}),
			pauseManager:        service.FromContext[pause.Manager](ctx),
			subInfo:             SubInfo{},
			outbounds:           []adapter.Outbound{},
			outboundByTag:       make(map[string]adapter.Outbound),
		},
	}
	if err := provider.firstStart(options.Ports); err != nil {
		return nil, err
	}
	return provider, nil
}

func (p *LocalProvider) Start() error {
	var history *urltest.HistoryStorage
	if history = service.PtrFromContext[urltest.HistoryStorage](p.ctx); history != nil {
	} else if clashServer := p.router.ClashServer(); clashServer != nil {
		history = clashServer.HistoryStorage()
	} else {
		history = urltest.NewHistoryStorage()
	}
	p.healchcheckHistory = history
	return nil
}

func (p *LocalProvider) loopCheck() {
	p.CheckOutbounds(true)
	for {
		select {
		case <-p.ctx.Done():
			return
		case <-p.ticker.C:
			p.pauseManager.WaitActive()
			p.CheckOutbounds(false)
		}
	}
}

func (p *LocalProvider) PostStart() error {
	p.ticker = time.NewTicker(1 * time.Minute)
	go p.loopCheck()
	return nil
}

func (p *LocalProvider) UpdateProvider(ctx context.Context, router adapter.Router, force bool) error {
	defer runtime.GC()
	if p.updating.Swap(true) {
		return E.New("provider is updating")
	}
	defer p.updating.Store(false)
	p.logger.Debug("updating outbound provider ", p.tag, " from local file")
	if !rw.FileExists(p.path) {
		return nil
	}
	fileInfo, _ := os.Stat(p.path)
	fileModeTime := fileInfo.ModTime()
	if fileModeTime == p.updateTime {
		return nil
	}

	info, content := p.getContentFromFile(router)
	if len(content) == 0 {
		return nil
	}

	updated, err := p.updateProviderFromContent(ctx, router, decodeBase64Safe(content))
	if err != nil {
		return err
	}

	p.subInfo = info
	p.updateTime = fileModeTime
	p.logger.Info("update outbound provider ", p.tag, " success")

	if updated {
		p.CheckOutbounds(true)
	}
	return nil
}
