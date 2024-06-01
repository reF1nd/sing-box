package provider

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"
)

var (
	_ adapter.OutboundProvider        = (*RemoteProvider)(nil)
	_ adapter.InterfaceUpdateListener = (*RemoteProvider)(nil)
)

type RemoteProvider struct {
	myProviderAdapter
	url         string
	ua          string
	interval    time.Duration
	lastUpdated time.Time
	lastEtag    string
	detour      string
	dialer      N.Dialer
}

func NewRemoteProvider(ctx context.Context, router adapter.Router, logger log.ContextLogger, options option.OutboundProvider, path string) (*RemoteProvider, error) {
	remoteOptions := options.RemoteOptions
	healthcheckInterval := time.Duration(options.HealthcheckInterval)
	if remoteOptions.Url == "" {
		return nil, E.New("missing url")
	}
	parsedURL, err := url.Parse(remoteOptions.Url)
	if err != nil {
		return nil, err
	}
	switch parsedURL.Scheme {
	case "":
		parsedURL.Scheme = "http"
	case "http", "https":
	default:
		return nil, E.New("invalid url scheme")
	}
	ua := remoteOptions.UserAgent
	downloadInterval := time.Duration(options.RemoteOptions.Interval)
	defaultDownloadInterval, _ := time.ParseDuration("1h")
	if ua == "" {
		ua = "sing-box " + C.Version + "; PuerNya fork"
	}
	if healthcheckInterval == 0 {
		healthcheckInterval = C.DefaultURLTestInterval
	}
	if downloadInterval < defaultDownloadInterval {
		downloadInterval = defaultDownloadInterval
	}
	ctx, cancel := context.WithCancel(ctx)
	provider := &RemoteProvider{
		myProviderAdapter: myProviderAdapter{
			ctx:                 ctx,
			cancel:              cancel,
			router:              router,
			logger:              logger,
			tag:                 options.Tag,
			path:                path,
			healthcheckUrl:      options.HealthcheckUrl,
			healthcheckInterval: healthcheckInterval,
			includes:            options.Includes,
			excludes:            options.Excludes,
			types:               options.Types,
			ports:               make(map[int]bool),
			providerType:        C.TypeRemoteProvider,
			overrideDialer:      options.OverrideDialer,
			close:               make(chan struct{}),
			pauseManager:        service.FromContext[pause.Manager](ctx),
			subInfo:             SubInfo{},
			outbounds:           []adapter.Outbound{},
			outboundByTag:       make(map[string]adapter.Outbound),
		},
		url:      parsedURL.String(),
		ua:       ua,
		interval: downloadInterval,
		detour:   remoteOptions.Detour,
	}
	if err := provider.firstStart(options.Ports); err != nil {
		return nil, err
	}
	return provider, nil
}

func (p *RemoteProvider) PostStart() error {
	var dialer N.Dialer
	if p.detour != "" {
		outbound, loaded := p.router.Outbound(p.detour)
		if !loaded {
			return E.New("download_detour not found: ", p.detour)
		}
		dialer = outbound
	} else {
		outbound, err := p.router.DefaultOutbound(N.NetworkTCP)
		if err != nil {
			return err
		}
		dialer = outbound
	}
	p.dialer = dialer
	p.ticker = time.NewTicker(1 * time.Minute)
	go p.loopCheck()
	return nil
}

func (p *RemoteProvider) Start() error {
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

func (p *RemoteProvider) loopCheck() {
	p.UpdateProvider(p.ctx, p.router, p.updateTime.IsZero())
	p.CheckOutbounds(true)
	for {
		select {
		case <-p.ctx.Done():
			return
		case <-p.ticker.C:
			p.pauseManager.WaitActive()
			p.UpdateProvider(p.ctx, p.router, false)
			p.CheckOutbounds(false)
		}
	}
}

func (p *RemoteProvider) updateCacheFileModTime(subInfo string) {
	info, ok := parseSubInfo(subInfo)
	if !ok {
		return
	}
	p.subInfo = info

	contentRaw := getTrimedFile(p.path)
	content := decodeBase64Safe(string(contentRaw))
	firstLine, others := getFirstLine(content)
	if _, ok := parseSubInfo(firstLine); ok {
		content = decodeBase64Safe(others)
	}
	infoStr := fmt.Sprint("# upload=", info.upload, "; download=", info.download, "; total=", info.total, "; expire=", info.expire, ";")
	content = infoStr + "\n" + content
	os.WriteFile(p.path, []byte(content), 0o666)
}

func (p *RemoteProvider) fetchOnce(ctx context.Context, router adapter.Router) error {
	defer runtime.GC()
	p.lastUpdated = time.Now()

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSHandshakeTimeout: C.TCPTimeout,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return p.dialer.DialContext(ctx, network, M.ParseSocksaddr(addr))
			},
		},
	}

	request, err := http.NewRequest("GET", p.url, nil)
	if err != nil {
		return err
	}

	if p.lastEtag != "" {
		request.Header.Set("If-None-Match", p.lastEtag)
	}

	request.Header.Set("User-Agent", p.ua)

	response, err := httpClient.Do(request)
	if err != nil {
		uErr := err.(*url.Error)
		return uErr.Err
	}

	subInfo := response.Header.Get("subscription-userinfo")

	switch response.StatusCode {
	case http.StatusOK:
	case http.StatusNotModified:
		p.logger.Info("update outbound provider ", p.tag, ": not modified")
		p.updateTime = p.lastUpdated
		p.updateCacheFileModTime(subInfo)
		return nil
	default:
		return E.New("unexpected status: ", response.Status)
	}

	defer response.Body.Close()

	contentRaw, err := io.ReadAll(response.Body)
	if err != nil {
		return err
	}
	if len(contentRaw) == 0 {
		return E.New("empty response")
	}

	eTagHeader := response.Header.Get("Etag")
	if eTagHeader != "" {
		p.lastEtag = eTagHeader
	}

	content := decodeBase64Safe(string(contentRaw))
	info, hasSubInfo := parseSubInfo(subInfo)

	if !hasSubInfo {
		var ok bool
		firstLine, others := getFirstLine(content)
		if info, ok = parseSubInfo(firstLine); ok {
			content = decodeBase64Safe(others)
			hasSubInfo = true
		}
	}

	updated, err := p.updateProviderFromContent(ctx, router, content)
	if err != nil {
		return err
	}

	p.subInfo = info
	p.updateTime = p.lastUpdated
	p.logger.Info("update outbound provider ", p.tag, " success")

	if hasSubInfo {
		subInfo = fmt.Sprint("# upload=", info.upload, "; download=", info.download, "; total=", info.total, "; expire=", info.expire, ";")
		content = subInfo + "\n" + content
	}

	os.WriteFile(p.path, []byte(content), 0o666)

	if updated {
		p.CheckOutbounds(true)
	}
	return nil
}

func (p *RemoteProvider) UpdateProvider(ctx context.Context, router adapter.Router, force bool) error {
	if p.updating.Swap(true) {
		return E.New("provider is updating")
	}
	defer p.updating.Store(false)

	if !force && time.Since(p.lastUpdated) < p.interval {
		return nil
	}

	p.logger.Debug("update outbound provider ", p.tag, " from network")

	err := p.fetchOnce(ctx, router)

	if err != nil {
		p.logger.Error(E.New("update outbound provider ", p.tag, " failed.", err))
	}

	return err
}
