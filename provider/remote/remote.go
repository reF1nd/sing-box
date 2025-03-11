package remote

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/provider"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/provider/parser"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/batch"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"
)

// RegisterRemote registers the remote provider.
func RegisterProvider(registry *provider.Registry) {
	provider.Register[option.ProviderRemoteOptions](registry, C.ProviderTypeRemote, NewProviderRemote)
}

var (
	_ adapter.Provider       = (*ProviderRemote)(nil)
	_ adapter.ProviderInfoer = (*ProviderRemote)(nil)
	_ adapter.Service        = (*ProviderRemote)(nil)
)

// ProviderRemote is a remote outbounds provider.
type ProviderRemote struct {
	access     sync.Mutex
	parentCtx  context.Context
	router     adapter.Router
	outbound   adapter.OutboundManager
	logFactory log.Factory
	logger     log.ContextLogger
	tag        string

	url            string
	path           string
	userAgent      string
	downloadDetour string
	updateInterval time.Duration
	exclude        *regexp.Regexp
	include        *regexp.Regexp

	providerInfo       *adapter.ProviderRemoteInfo
	ctx                context.Context
	cancel             context.CancelFunc
	contentStr         string
	callbacks          list.List[adapter.ProviderUpdateCallback]
	dialer             N.Dialer
	healchcheckHistory adapter.URLTestHistoryStorage
	lastEtag           string
	outbounds          []adapter.Outbound
	outboundsByTag     map[string]adapter.Outbound
	pauseManager       pause.Manager
}

// NewProviderRemote creates a new remote provider.
func NewProviderRemote(ctx context.Context, router adapter.Router, logFactory log.Factory, tag string, options option.ProviderRemoteOptions) (adapter.Provider, error) {
	if tag == "" {
		return nil, E.New("provider tag is required")
	}
	if options.URL == "" {
		return nil, E.New("provider URL is required")
	}
	var (
		err              error
		exclude, include *regexp.Regexp
	)
	if options.Exclude != "" {
		exclude, err = regexp.Compile(options.Exclude)
		if err != nil {
			return nil, err
		}
	}
	if options.Include != "" {
		include, err = regexp.Compile(options.Include)
		if err != nil {
			return nil, err
		}
	}
	updateInterval := time.Duration(options.UpdateInterval)
	if updateInterval <= 0 {
		// default to 24 hour
		updateInterval = 24 * time.Hour
	}
	if updateInterval < time.Minute {
		// minimum interval is 1 minute
		updateInterval = time.Minute
	}
	var userAgent string
	if options.UserAgent == "" {
		userAgent = "sing-box " + C.Version
	} else {
		userAgent = options.UserAgent
	}
	logger := logFactory.NewLogger(F.ToString("provider/remote", "[", tag, "]"))
	return &ProviderRemote{
		router:       router,
		logger:       logger,
		parentCtx:    ctx,
		logFactory:   logFactory,
		outbound:     service.FromContext[adapter.OutboundManager](ctx),
		pauseManager: service.FromContext[pause.Manager](ctx),

		tag:            tag,
		url:            options.URL,
		path:           options.Path,
		userAgent:      userAgent,
		downloadDetour: options.DownloadDetour,
		updateInterval: updateInterval,
		exclude:        exclude,
		include:        include,

		ctx:          ctx,
		providerInfo: &adapter.ProviderRemoteInfo{},
	}, nil
}

// Type returns the type of the provider.
func (s *ProviderRemote) Type() string {
	return C.ProviderTypeRemote
}

// Tag returns the tag of the provider.
func (s *ProviderRemote) Tag() string {
	return s.tag
}

// Info implements Infoer
func (s *ProviderRemote) Info() *adapter.ProviderRemoteInfo {
	return s.providerInfo
}

// Start starts the provider.
func (s *ProviderRemote) Start() error {
	s.access.Lock()
	defer s.access.Unlock()

	if s.cancel != nil {
		return nil
	}
	var dialer N.Dialer
	if s.downloadDetour != "" {
		outbound, loaded := s.outbound.Outbound(s.downloadDetour)
		if !loaded {
			return E.New("detour outbound not found: ", s.downloadDetour)
		}
		dialer = outbound
	} else {
		dialer = s.outbound.Default()
	}
	s.dialer = dialer
	s.ctx, s.cancel = context.WithCancel(s.ctx)
	s.healchcheckHistory = service.FromContext[adapter.URLTestHistoryStorage](s.ctx)
	if s.healchcheckHistory == nil {
		if clashServer := service.FromContext[adapter.ClashServer](s.ctx); clashServer != nil {
			s.healchcheckHistory = clashServer.HistoryStorage()
		} else {
			s.healchcheckHistory = urltest.NewHistoryStorage()
		}
	}
	go s.loopUpdate()
	return nil
}

// Close closes the service.
func (s *ProviderRemote) Close() error {
	if s.cancel != nil {
		s.cancel()
	}
	s.access.Lock()
	defer s.access.Unlock()
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

// Outbounds returns all the outbounds from the provider.
func (s *ProviderRemote) Outbounds() []adapter.Outbound {
	s.access.Lock()
	defer s.access.Unlock()
	return s.outbounds
}

// Outbound returns the outbound from the provider.
func (s *ProviderRemote) Outbound(tag string) (adapter.Outbound, bool) {
	s.access.Lock()
	defer s.access.Unlock()
	if s.outboundsByTag == nil {
		return nil, false
	}
	detour, ok := s.outboundsByTag[tag]
	return detour, ok
}

// RegisterCallback implements adapter.Provider.
func (s *ProviderRemote) RegisterCallback(callback adapter.ProviderUpdateCallback) *list.Element[adapter.ProviderUpdateCallback] {
	s.access.Lock()
	defer s.access.Unlock()
	return s.callbacks.PushBack(callback)
}

// UnregisterCallback implements adapter.Provider.
func (s *ProviderRemote) UnregisterCallback(element *list.Element[adapter.ProviderUpdateCallback]) {
	s.access.Lock()
	defer s.access.Unlock()
	s.callbacks.Remove(element)
}

// UpdatedAt implements adapter.Provider
func (s *ProviderRemote) UpdatedAt() time.Time {
	s.access.Lock()
	defer s.access.Unlock()
	return s.providerInfo.LastUpdated
}

// Update fetches and updates outbounds from the provider.
func (s *ProviderRemote) Update() error {
	s.access.Lock()
	defer s.access.Unlock()

	s.logger.DebugContext(s.ctx, "update outbound provider ", s.tag, " from network")

	if err := s.fetchOnce(s.ctx); err != nil {
		return E.New("update outbound provider ", s.tag, " failed.", err)
	}

	return nil
}

func (s *ProviderRemote) createOutbounds(opts []option.Outbound) {
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

func (s *ProviderRemote) fetchOnce(ctx context.Context) error {
	client := &http.Client{
		Transport: &http.Transport{
			ForceAttemptHTTP2:   true,
			TLSHandshakeTimeout: C.TCPTimeout,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return s.dialer.DialContext(ctx, network, M.ParseSocksaddr(addr))
			},
		},
	}
	req, err := http.NewRequest(http.MethodGet, s.url, nil)
	if err != nil {
		return err
	}
	if s.lastEtag != "" {
		req.Header.Set("If-None-Match", s.lastEtag)
	}
	req.Header.Set("User-Agent", s.userAgent)
	resp, err := client.Do(req.WithContext(ctx))
	if err != nil {
		return err
	}
	infoStr := resp.Header.Get("subscription-userinfo")
	info, hasInfo := parseInfo(infoStr)
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotModified:
		s.logger.InfoContext(ctx, "update outbound provider ", s.tag, ": not modified")
		s.providerInfo = info
		s.svaeCacheFile(info)
		return nil
	default:
		return E.New("unexpected status: ", resp.Status)
	}
	defer resp.Body.Close()
	contentRaw, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if len(contentRaw) == 0 {
		return E.New("empty response")
	}

	eTagHeader := resp.Header.Get("Etag")
	if eTagHeader != "" {
		s.lastEtag = eTagHeader
	}
	content := decodeBase64Safe(string(contentRaw))
	if !hasInfo {
		var ok bool
		firstLine, others := getFirstLine(content)
		if info, ok = parseInfo(firstLine); ok {
			content = decodeBase64Safe(others)
		}
	}
	if err := s.updateProviderFromContent(ctx, content); err != nil {
		return err
	}

	s.logger.InfoContext(ctx, "update outbound provider ", s.tag, " success")
	s.providerInfo = info
	s.contentStr = content
	s.svaeCacheFile(info)
	return nil
}

func (s *ProviderRemote) healthcheck(ctx context.Context) {
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

func (s *ProviderRemote) loadCacheFile(ctx context.Context) error {
	contentRaw, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}
	content := decodeBase64Safe(string(contentRaw))
	firstLine, others := getFirstLine(content)
	info, _ := parseInfo(firstLine)
	s.access.Lock()
	defer s.access.Unlock()
	s.contentStr = others
	s.providerInfo = info
	if err := s.updateProviderFromContent(ctx, others); err != nil {
		return err
	}
	return nil
}

func (s *ProviderRemote) loopUpdate() {
	updateTicker := time.NewTicker(s.updateInterval)
	defer updateTicker.Stop()
	var err error
	if err := s.loadCacheFile(s.ctx); err != nil {
		s.logger.Error(err)
	}
	if time.Since(s.providerInfo.LastUpdated) < s.updateInterval {
		select {
		case <-s.ctx.Done():
			return
		case <-time.After(time.Until(s.providerInfo.LastUpdated.Add(s.updateInterval))):
			s.pauseManager.WaitActive()
			err = s.Update()
			if err == nil {
				updateTicker.Reset(s.updateInterval)
			}
		}
	} else {
		err = s.Update()
	}
	if err != nil {
		s.logger.Error(err)
	}

L:
	for {
		runtime.GC()
		select {
		case <-s.ctx.Done():
			break L
		case <-updateTicker.C:
			s.pauseManager.WaitActive()
			if err := s.Update(); err != nil {
				s.logger.Error(err)
			}
		}
	}
}

func (s *ProviderRemote) removeUseless(outbounds []option.Outbound) {
	existed := make(map[string]bool)
	for _, outbound := range outbounds {
		tag := s.Tag() + "/" + outbound.Tag
		existed[tag] = true
	}
	for _, outbound := range s.outbounds {
		if !existed[outbound.Tag()] {
			err := s.outbound.Remove(outbound.Tag())
			if err != nil {
				s.logger.Error(err, "remove outbound [", outbound.Tag(), "]")
			}
		}
	}
}

func (s *ProviderRemote) svaeCacheFile(info *adapter.ProviderRemoteInfo) {
	infoStr := fmt.Sprint(
		"# upload=", info.Upload,
		"; download=", info.Download,
		"; total=", info.Total,
		"; expire=", info.Expire,
		"; updated=", s.providerInfo.LastUpdated.Unix(),
		";")
	content := infoStr + "\n" + s.contentStr
	dir := filepath.Dir(s.path)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		os.MkdirAll(dir, 0o755)
	}
	os.WriteFile(s.path, []byte(content), 0o666)
}

func (s *ProviderRemote) updateProviderFromContent(ctx context.Context, content string) error {
	outbounds, err := parser.ParseSubscription(ctx, content)
	if err != nil {
		return err
	}
	outbounds = common.Filter(outbounds, func(it option.Outbound) bool {
		return (s.include == nil || s.include.MatchString(it.Tag)) && (s.exclude == nil || !s.exclude.MatchString(it.Tag))
	})
	s.createOutbounds(outbounds)
	callbacks := s.callbacks.Array()
	for _, callback := range callbacks {
		callback(s.tag, s.outbounds)
	}
	s.healthcheck(ctx)
	return nil
}
