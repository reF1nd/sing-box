package remote

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/provider"
	"github.com/sagernet/sing-box/common/hash"
	"github.com/sagernet/sing-box/common/interrupt"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/experimental/deprecated"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/provider/parser"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/filemanager"
)

func RegisterProvider(registry *provider.Registry) {
	provider.Register[option.ProviderRemoteOptions](registry, C.ProviderTypeRemote, NewProviderRemote)
}

var _ adapter.Provider = (*ProviderRemote)(nil)

type ProviderRemote struct {
	provider.Adapter
	ctx              context.Context
	cancel           context.CancelFunc
	logger           log.ContextLogger
	outbound         adapter.OutboundManager
	provider         adapter.ProviderManager
	cacheFile        adapter.CacheFile
	httpClient       *http.Client
	hash             hash.HashType
	infoMu           sync.RWMutex
	lastEtag         string
	lastOutOpts      []option.Outbound
	lastEPOpts       []option.Endpoint
	lastUpdated      time.Time
	subscriptionInfo adapter.SubscriptionInfo
	ticker           *time.Ticker
	updating         atomic.Bool

	httpClientOptions *option.HTTPClientOptions
	downloadDetour    string
	url               string
	urlHash           [32]byte
	path              string
	initialPath       string
	userAgent         string
	updateInterval    time.Duration
	exclude           *regexp.Regexp
	include           *regexp.Regexp

	overrideDialer *option.OverrideDialerOptions
	overrideTLS    *option.OverrideTLSOptions
	overrideAnyTLS *option.OverrideAnyTLSOptions
}

func NewProviderRemote(ctx context.Context, router adapter.Router, logFactory log.Factory, tag string, options option.ProviderRemoteOptions) (adapter.Provider, error) {
	if options.URL == "" {
		return nil, E.New("provider URL is required")
	}
	if options.Path != "" && options.InitialPath != "" {
		return nil, E.New("provider path and initial_path are mutually exclusive")
	}
	var (
		path        string
		initialPath string
	)
	if options.Path != "" {
		path = filemanager.BasePath(ctx, options.Path)
		path, _ = filepath.Abs(path)
	}
	if options.InitialPath != "" {
		initialPath = filemanager.BasePath(ctx, options.InitialPath)
		initialPath, _ = filepath.Abs(initialPath)
	}
	if path != "" {
		info, err := filemanager.Stat(ctx, path)
		if err == nil && info.IsDir() {
			return nil, E.New("provider path is a directory: ", path)
		}
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, E.Cause(err, "check provider path")
		}
	}
	if initialPath != "" {
		info, err := filemanager.Stat(ctx, initialPath)
		if err == nil && info.IsDir() {
			return nil, E.New("provider initial_path is a directory: ", initialPath)
		}
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, E.Cause(err, "check provider initial_path")
		}
	}
	updateInterval := time.Duration(options.UpdateInterval)
	if updateInterval <= 0 {
		updateInterval = 24 * time.Hour
	}
	if updateInterval < time.Hour {
		updateInterval = time.Hour
	}
	if options.UserAgent != "" && options.HTTPClient != nil && !options.HTTPClient.IsEmpty() {
		return nil, E.New("user_agent conflicts with http_client: configure User-Agent via http_client.headers instead")
	}
	var userAgent string
	if options.UserAgent == "" {
		userAgent = "sing-box " + C.Version
	} else {
		userAgent = options.UserAgent
	}
	ctx, cancel := context.WithCancel(ctx)
	outbound := service.FromContext[adapter.OutboundManager](ctx)
	endpointMgr := service.FromContext[adapter.EndpointManager](ctx)
	logger := logFactory.NewLogger(F.ToString("provider/remote", "[", tag, "]"))
	url := options.URL
	return &ProviderRemote{
		Adapter:  provider.NewAdapter(ctx, router, outbound, endpointMgr, logFactory, logger, tag, C.ProviderTypeRemote, options.HealthCheck),
		ctx:      ctx,
		cancel:   cancel,
		logger:   logger,
		outbound: outbound,
		provider: service.FromContext[adapter.ProviderManager](ctx),

		httpClientOptions: options.HTTPClient,
		url:               url,
		urlHash:           sha256.Sum256([]byte(url)),
		path:              path,
		initialPath:       initialPath,
		userAgent:         userAgent,
		updateInterval:    updateInterval,
		exclude:           (*regexp.Regexp)(options.Exclude),
		include:           (*regexp.Regexp)(options.Include),

		overrideDialer: options.OverrideDialer,
		overrideTLS:    options.OverrideTLS,
		overrideAnyTLS: options.OverrideAnyTLS,

		//nolint:staticcheck
		downloadDetour: options.DownloadDetour,
	}, nil
}

func (s *ProviderRemote) StartContext(ctx context.Context, startContext *adapter.HTTPStartContext) error {
	s.cacheFile = service.FromContext[adapter.CacheFile](s.ctx)
	if s.initialPath != "" && s.cacheFile == nil {
		return E.New("provider initial_path requires cache_file")
	}
	loadedFromCache, err := s.loadCacheFile()
	if err != nil {
		s.logger.Warn(E.Cause(err, "restore cached outbound provider, will refetch"))
	}
	var loadedFromInitialPath bool
	if !loadedFromCache && s.initialPath != "" {
		err = s.loadInitialPath()
		if err != nil {
			s.logger.Warn(E.Cause(err, "load initial outbound provider from ", s.initialPath))
		} else {
			loadedFromInitialPath = true
		}
	}
	transport, err := s.resolveTransport()
	if err != nil {
		return E.Cause(err, "create provider http client")
	}
	startContext.Register(transport)
	s.httpClient = &http.Client{Transport: transport}
	if !loadedFromCache && !loadedFromInitialPath {
		ctx = interrupt.ContextWithIsProviderConnection(ctx)
		err = s.fetch(ctx, true)
		if err != nil {
			return E.Cause(err, "initial outbound provider: ", s.Tag())
		}
	}
	s.ticker = time.NewTicker(s.updateInterval)
	go s.loopUpdate()
	return s.Adapter.Start()
}

func (s *ProviderRemote) Update() error {
	if s.ticker != nil {
		s.ticker.Reset(s.updateInterval)
	}
	ctx := interrupt.ContextWithIsProviderConnection(s.ctx)
	return s.fetch(ctx, false)
}

func (s *ProviderRemote) UpdatedAt() time.Time {
	s.infoMu.RLock()
	defer s.infoMu.RUnlock()
	return s.lastUpdated
}

func (s *ProviderRemote) SubscriptionInfo() adapter.SubscriptionInfo {
	s.infoMu.RLock()
	defer s.infoMu.RUnlock()
	return s.subscriptionInfo
}

func (s *ProviderRemote) Close() error {
	s.cancel()
	if s.ticker != nil {
		s.ticker.Stop()
	}
	return common.Close(&s.Adapter)
}

func (s *ProviderRemote) resolveTransport() (adapter.HTTPTransport, error) {
	httpClientManager := service.FromContext[adapter.HTTPClientManager](s.ctx)
	if s.httpClientOptions != nil && !s.httpClientOptions.IsEmpty() {
		if s.downloadDetour != "" {
			return nil, E.New("http_client is conflict with deprecated download_detour field")
		}
		return httpClientManager.ResolveTransport(s.ctx, s.logger, *s.httpClientOptions)
	}
	if s.downloadDetour != "" {
		deprecated.Report(s.ctx, deprecated.OptionLegacyProviderDownloadDetour)
		return httpClientManager.ResolveTransport(s.ctx, s.logger, option.HTTPClientOptions{
			DialerOptions: option.DialerOptions{
				Detour: s.downloadDetour,
			},
			DisableEmptyDirectCheck: true,
		})
	}
	defaultTransport := httpClientManager.DefaultTransport()
	if defaultTransport == nil {
		return nil, E.New("default http client transport is not initialized")
	}
	return defaultTransport, nil
}

func (s *ProviderRemote) updateOnce() {
	ctx := interrupt.ContextWithIsProviderConnection(s.ctx)
	if err := s.fetch(ctx, false); err != nil {
		s.logger.Error("update outbound provider: ", err)
	}
}

func (s *ProviderRemote) fetch(ctx context.Context, isStart bool) error {
	if s.updating.Swap(true) {
		return E.New("provider is updating")
	}
	defer s.updating.Store(false)
	s.logger.Debug("updating outbound provider ", s.Tag(), " from URL: ", s.url)
	req, err := http.NewRequest(http.MethodGet, s.url, nil)
	if err != nil {
		return err
	}
	if s.lastEtag != "" {
		req.Header.Set("If-None-Match", s.lastEtag)
	}
	req.Header.Set("User-Agent", s.userAgent)
	if !isStart {
		defer s.httpClient.CloseIdleConnections()
	}
	resp, err := s.httpClient.Do(req.WithContext(ctx))
	if err != nil {
		return err
	}
	infoStr := resp.Header.Get("subscription-userinfo")
	info, hasInfo := parseInfo(infoStr)
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotModified:
		s.infoMu.Lock()
		s.subscriptionInfo = info
		s.lastUpdated = time.Now()
		s.infoMu.Unlock()
		if s.cacheFile != nil {
			saveSub := s.cacheFile.LoadSubscription(s.Tag())
			if saveSub != nil {
				if s.path != "" {
					saveSub.Hash = s.hash
				} else if hasInfo {
					index := bytes.IndexByte(saveSub.Content, '\n')
					if index != -1 {
						saveSub.Content = append([]byte(infoStr+"\n"), saveSub.Content[index+1:]...)
					}
				}
				saveSub.LastUpdated = s.lastUpdated
				saveSub.URLHash = s.urlHash[:]
				if err := s.cacheFile.SaveSubscription(s.Tag(), saveSub); err != nil {
					s.logger.Error("save outbound provider cache file: ", err)
				}
			}
		}
		if s.path != "" {
			content, _ := json.Marshal(option.Options{
				Outbounds: s.lastOutOpts,
				Endpoints: s.lastEPOpts,
			})
			if err := s.saveCacheFile(hasInfo, info, content); err != nil {
				return E.Cause(err, "save outbound provider cache file")
			}
		}
		s.logger.Info("update outbound provider ", s.Tag(), ": not modified")
		return nil
	default:
		return E.New("unexpected status: ", resp.Status)
	}
	defer resp.Body.Close()
	contentRaw, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	eTagHeader := resp.Header.Get("Etag")
	if eTagHeader != "" {
		s.infoMu.Lock()
		s.lastEtag = eTagHeader
		s.infoMu.Unlock()
	}
	content, _ := parser.DecodeBase64URLSafe(string(contentRaw))
	if !hasInfo {
		firstLine, others := getFirstLine(content)
		if info, hasInfo = parseInfo(firstLine); hasInfo {
			infoStr = firstLine
			content, _ = parser.DecodeBase64URLSafe(others)
		}
	}
	if err := s.updateProviderFromContent(content); err != nil {
		return err
	}
	s.UpdateGroups()
	s.infoMu.Lock()
	s.subscriptionInfo = info
	s.lastUpdated = time.Now()
	s.infoMu.Unlock()
	if s.path != "" || s.cacheFile != nil {
		content, _ := json.Marshal(option.Options{
			Outbounds: s.lastOutOpts,
			Endpoints: s.lastEPOpts,
		})
		if s.path != "" {
			if err = s.saveCacheFile(hasInfo, info, content); err != nil {
				return E.Cause(err, "save outbound provider cache file")
			}
		} else if hasInfo {
			content = append([]byte(infoStr+"\n"), content...)
		}
		if s.cacheFile != nil {
			saveSub := &adapter.SavedBinary{
				LastUpdated: s.lastUpdated,
				LastEtag:    s.lastEtag,
				URLHash:     s.urlHash[:],
			}
			if s.path != "" {
				saveSub.Hash = s.hash
			} else {
				saveSub.Content = content
			}
			if err = s.cacheFile.SaveSubscription(s.Tag(), saveSub); err != nil {
				s.logger.Error("save outbound provider cache file: ", err)
			}
		}
	}
	s.logger.Info("updated outbound provider ", s.Tag())
	return nil
}

func (s *ProviderRemote) loadCacheFile() (bool, error) {
	var content []byte
	var lastUpdated time.Time
	var lastEtag string
	var saveSub *adapter.SavedBinary
	if s.cacheFile != nil {
		if saveSub = s.cacheFile.LoadSubscription(s.Tag()); saveSub != nil {
			if len(saveSub.URLHash) > 0 && !bytes.Equal(saveSub.URLHash, s.urlHash[:]) {
				s.logger.Info("cached outbound provider was downloaded from another URL, will refetch")
				return false, nil
			}
			s.hash = saveSub.Hash
		}
	}
	if s.path != "" {
		exists, err := pathExists(s.ctx, s.path)
		if err != nil {
			return false, err
		}
		if !exists {
			return false, nil
		}
		file, err := filemanager.Open(s.ctx, s.path)
		if err != nil {
			return false, err
		}
		content, err = io.ReadAll(file)
		if err != nil {
			file.Close()
			return false, err
		}
		fileInfo, err := file.Stat()
		closeErr := file.Close()
		if err != nil {
			return false, err
		}
		if closeErr != nil {
			return false, closeErr
		}
		if saveSub != nil {
			if !s.hash.Equal(hash.MakeHash(content)) {
				return false, E.New("load outbound provider cache file failed: validation failed")
			}
			lastUpdated = saveSub.LastUpdated
			lastEtag = saveSub.LastEtag
		} else {
			lastUpdated = fileInfo.ModTime()
		}
	} else if saveSub != nil && len(saveSub.Content) > 0 {
		content = saveSub.Content
		lastUpdated = saveSub.LastUpdated
		lastEtag = saveSub.LastEtag
	} else {
		return false, nil
	}
	if err := s.loadFromContent(content); err != nil {
		return false, err
	}
	s.UpdateGroups()
	s.lastUpdated, s.lastEtag = lastUpdated, lastEtag
	return true, nil
}

func (s *ProviderRemote) loadInitialPath() error {
	contentRaw, err := filemanager.ReadFile(s.ctx, s.initialPath)
	if err != nil {
		return err
	}
	content := s.decodeContent(contentRaw)
	err = s.updateProviderFromContent(content)
	if err != nil {
		return err
	}
	s.UpdateGroups()
	return nil
}

func (s *ProviderRemote) loadFromContent(contentRaw []byte) error {
	content := s.decodeContent(contentRaw)
	outboundOpts, endpointOpts, err := parser.ParseBoxSubscription(s.ctx, content)
	if err != nil {
		return err
	}
	s.UpdateOutbounds(s.lastOutOpts, outboundOpts)
	s.lastOutOpts = outboundOpts
	s.UpdateEndpoints(s.lastEPOpts, endpointOpts)
	s.lastEPOpts = endpointOpts
	return nil
}

func (s *ProviderRemote) decodeContent(contentRaw []byte) string {
	content, _ := parser.DecodeBase64URLSafe(string(contentRaw))
	firstLine, others := getFirstLine(content)
	if info, ok := parseInfo(firstLine); ok {
		s.infoMu.Lock()
		s.subscriptionInfo = info
		s.infoMu.Unlock()
		content, _ = parser.DecodeBase64URLSafe(others)
	}
	return content
}

func pathExists(ctx context.Context, path string) (bool, error) {
	info, err := filemanager.Stat(ctx, path)
	if err == nil {
		if info.IsDir() {
			return false, E.New("provider path is a directory: ", path)
		}
		return true, nil
	}
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	return false, err
}

func (s *ProviderRemote) loopUpdate() {
	s.ticker.Stop()
	select {
	case <-s.ticker.C:
	default:
	}
	if remaining := time.Until(func() time.Time {
		s.infoMu.RLock()
		defer s.infoMu.RUnlock()
		return s.lastUpdated
	}().Add(s.updateInterval)); remaining > 0 {
		s.ticker.Reset(remaining)
	} else {
		s.updateOnce()
		s.ticker.Reset(s.updateInterval)
	}
	for {
		runtime.GC()
		select {
		case <-s.ctx.Done():
			return
		case <-s.ticker.C:
			s.updateOnce()
			s.ticker.Reset(s.updateInterval)
		}
	}
}

func (s *ProviderRemote) saveCacheFile(hasInfo bool, info adapter.SubscriptionInfo, contentRaw []byte) error {
	content := contentRaw
	if hasInfo {
		infoStr := fmt.Sprint(
			"# upload=", info.Upload,
			"; download=", info.Download,
			"; total=", info.Total,
			"; expire=", info.Expire,
			";")
		content = append([]byte(infoStr+"\n"), content...)
	}
	dir := filepath.Dir(s.path)
	err := filemanager.MkdirAll(s.ctx, dir, 0o755)
	if err != nil {
		return err
	}
	err = filemanager.WriteFile(s.ctx, s.path, content, 0o666)
	if err != nil {
		return err
	}
	s.hash = hash.MakeHash(content)
	return nil
}

func (s *ProviderRemote) updateProviderFromContent(content string) error {
	outboundOpts, endpointOpts, err := parser.ParseSubscription(s.ctx, content, s.overrideDialer, s.overrideTLS, s.overrideAnyTLS, s.Tag())
	if err != nil {
		return err
	}
	outboundOpts = common.Filter(outboundOpts, func(it option.Outbound) bool {
		return (s.exclude == nil || !s.exclude.MatchString(it.Tag)) && (s.include == nil || s.include.MatchString(it.Tag))
	})
	endpointOpts = common.Filter(endpointOpts, func(it option.Endpoint) bool {
		return (s.exclude == nil || !s.exclude.MatchString(it.Tag)) && (s.include == nil || s.include.MatchString(it.Tag))
	})
	s.UpdateOutbounds(s.lastOutOpts, outboundOpts)
	s.lastOutOpts = outboundOpts
	s.UpdateEndpoints(s.lastEPOpts, endpointOpts)
	s.lastEPOpts = endpointOpts
	return nil
}

func getFirstLine(content string) (string, string) {
	lines := strings.Split(content, "\n")
	if len(lines) == 1 {
		return lines[0], ""
	}
	others := strings.Join(lines[1:], "\n")
	return lines[0], others
}

func parseInfo(infoStr string) (adapter.SubscriptionInfo, bool) {
	info := adapter.SubscriptionInfo{}
	if infoStr == "" {
		return info, false
	}
	reg := regexp.MustCompile(`(upload|download|total|expire)[\s\t]*=[\s\t]*(-?\d*);?`)
	matches := reg.FindAllStringSubmatch(infoStr, 4)
	if len(matches) == 0 {
		return info, false
	}
	for _, match := range matches {
		key, value := match[1], match[2]
		switch key {
		case "upload":
			info.Upload = parser.StringToType[int64](value)
		case "download":
			info.Download = parser.StringToType[int64](value)
		case "total":
			info.Total = parser.StringToType[int64](value)
		case "expire":
			info.Expire = parser.StringToType[int64](value)
		default:
			return info, false
		}
	}
	return info, true
}
