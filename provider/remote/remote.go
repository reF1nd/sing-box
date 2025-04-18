package remote

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/provider"
	"github.com/sagernet/sing-box/common/hash"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/provider/parser"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ntp"
	"github.com/sagernet/sing/common/rw"
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
	dialer           N.Dialer
	hash             hash.HashType
	lastEtag         string
	lastOutOpts      []option.Outbound
	lastUpdated      time.Time
	subscriptionInfo adapter.SubscriptionInfo
	ticker           *time.Ticker
	updating         atomic.Bool
	update           chan struct{}

	url            string
	path           string
	userAgent      string
	downloadDetour string
	updateInterval time.Duration
	exclude        *regexp.Regexp
	include        *regexp.Regexp
}

func NewProviderRemote(ctx context.Context, router adapter.Router, logFactory log.Factory, tag string, options option.ProviderRemoteOptions) (adapter.Provider, error) {
	if options.URL == "" {
		return nil, E.New("provider URL is required")
	}
	var path string
	if options.Path != "" {
		path = filemanager.BasePath(ctx, options.Path)
		path, _ = filepath.Abs(path)
	}
	if rw.IsDir(path) {
		return nil, E.New("provider path is a directory: ", path)
	}
	updateInterval := time.Duration(options.UpdateInterval)
	if updateInterval <= 0 {
		updateInterval = 24 * time.Hour
	}
	if updateInterval < time.Hour {
		updateInterval = time.Hour
	}
	var userAgent string
	if options.UserAgent == "" {
		userAgent = "sing-box " + C.Version
	} else {
		userAgent = options.UserAgent
	}
	ctx, cancel := context.WithCancel(ctx)
	outbound := service.FromContext[adapter.OutboundManager](ctx)
	logger := logFactory.NewLogger(F.ToString("provider/remote", "[", tag, "]"))
	updateChan := make(chan struct{})
	close(updateChan)
	return &ProviderRemote{
		Adapter:  provider.NewAdapter(ctx, router, outbound, logFactory, logger, tag, C.ProviderTypeRemote, options.HealthCheck),
		ctx:      ctx,
		cancel:   cancel,
		logger:   logger,
		outbound: outbound,
		provider: service.FromContext[adapter.ProviderManager](ctx),
		update:   updateChan,

		url:            options.URL,
		path:           path,
		userAgent:      userAgent,
		downloadDetour: options.DownloadDetour,
		updateInterval: updateInterval,
		exclude:        (*regexp.Regexp)(options.Exclude),
		include:        (*regexp.Regexp)(options.Include),
	}, nil
}

func (s *ProviderRemote) Start() error {
	s.cacheFile = service.FromContext[adapter.CacheFile](s.ctx)
	err := s.loadCacheFile()
	if err != nil {
		return E.Cause(err, "restore cached outbound provider")
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
	return nil
}

func (s *ProviderRemote) PostStart() error {
	if err := s.Adapter.PostStart(); err != nil {
		return err
	}
	go s.loopUpdate()
	return nil
}

func (s *ProviderRemote) Update() error {
	if s.ticker != nil {
		s.ticker.Reset(s.updateInterval)
	}
	return s.fetch(s.ctx)
}

func (s *ProviderRemote) UpdatedAt() time.Time {
	return s.lastUpdated
}

func (s *ProviderRemote) SubscriptionInfo() adapter.SubscriptionInfo {
	return s.subscriptionInfo
}

func (s *ProviderRemote) Wait() {
	if s.updating.Load() {
		<-s.update
	}
}

func (s *ProviderRemote) Close() error {
	s.cancel()
	if s.ticker != nil {
		s.ticker.Stop()
	}
	return common.Close(&s.Adapter)
}

func (s *ProviderRemote) updateOnce() {
	if err := s.fetch(s.ctx); err != nil {
		s.logger.Error("update outbound provider: ", err)
	}
}

func (s *ProviderRemote) fetch(ctx context.Context) error {
	if s.updating.Swap(true) {
		return E.New("provider is updating")
	}
	s.update = make(chan struct{})
	defer func() {
		close(s.update)
		s.updating.Store(false)
	}()
	s.logger.Debug("updating outbound provider ", s.Tag(), " from URL: ", s.url)
	client := &http.Client{
		Transport: &http.Transport{
			ForceAttemptHTTP2:   true,
			TLSHandshakeTimeout: C.TCPTimeout,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return s.dialer.DialContext(ctx, network, M.ParseSocksaddr(addr))
			},
			TLSClientConfig: &tls.Config{
				Time:    ntp.TimeFuncFromContext(ctx),
				RootCAs: adapter.RootPoolFromContext(ctx),
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
		s.subscriptionInfo = info
		s.lastUpdated = time.Now()
		var saveSub *adapter.SavedBinary
		if s.cacheFile != nil {
			saveSub = s.cacheFile.LoadSubscription(s.Tag())
		}
		if s.path != "" {
			content, _ := json.Marshal(option.Options{
				Outbounds: s.lastOutOpts,
			})
			s.saveCacheFile(hasInfo, info, content)
			if saveSub != nil {
				saveSub.Hash = s.hash
				saveSub.LastUpdated = s.lastUpdated
				err := s.cacheFile.SaveSubscription(s.Tag(), saveSub)
				if err != nil {
					s.logger.Error("save outbound provider cache file: ", err)
					return nil
				}
			}
		} else if saveSub != nil {
			if hasInfo {
				index := bytes.IndexByte(saveSub.Content, '\n')
				if index != -1 {
					saveSub.Content = append([]byte(infoStr+"\n"), saveSub.Content[index+1:]...)
				}
			}
			saveSub.LastUpdated = s.lastUpdated
			err := s.cacheFile.SaveSubscription(s.Tag(), saveSub)
			if err != nil {
				s.logger.Error("save outbound provider cache file: ", err)
				return nil
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
		s.lastEtag = eTagHeader
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
	s.subscriptionInfo = info
	s.lastUpdated = time.Now()
	if s.path != "" || s.cacheFile != nil {
		content, _ := json.Marshal(option.Options{
			Outbounds: s.lastOutOpts,
		})
		if s.path != "" {
			s.saveCacheFile(hasInfo, info, content)
			if s.cacheFile != nil {
				err = s.cacheFile.SaveSubscription(s.Tag(), &adapter.SavedBinary{
					Hash:        s.hash,
					LastUpdated: s.lastUpdated,
					LastEtag:    s.lastEtag,
				})
			}
		} else if s.cacheFile != nil {
			if hasInfo {
				content = append([]byte(infoStr+"\n"), content...)
			}
			err = s.cacheFile.SaveSubscription(s.Tag(), &adapter.SavedBinary{
				LastUpdated: s.lastUpdated,
				Content:     content,
				LastEtag:    s.lastEtag,
			})
		}
		if err != nil {
			s.logger.Error("save outbound provider cache file: ", err)
		}
	}
	s.logger.Info("updated outbound provider ", s.Tag())
	return nil
}

func (s *ProviderRemote) loadCacheFile() error {
	var saveSub *adapter.SavedBinary
	if s.cacheFile != nil {
		if saveSub = s.cacheFile.LoadSubscription(s.Tag()); saveSub != nil {
			s.hash = saveSub.Hash
		}
	}
	if s.path != "" {
		pathIsExists, err := pathExists(s.path)
		if err != nil {
			return err
		}
		if !pathIsExists {
			return nil
		}
		file, _ := os.Open(s.path)
		content, err := io.ReadAll(file)
		if err != nil {
			return err
		}
		var lastUpdated time.Time
		var lastEtag string
		if saveSub != nil {
			hash := hash.MakeHash(content)
			if !s.hash.Equal(hash) {
				s.logger.Error("load outbound provider cache file failed: validation failed")
				return nil
			}
			lastUpdated = saveSub.LastUpdated
			lastEtag = saveSub.LastEtag
		} else {
			fs, _ := file.Stat()
			lastUpdated = fs.ModTime()
		}
		err = s.loadFromContent(content)
		if err != nil {
			return err
		}
		s.lastUpdated = lastUpdated
		s.lastEtag = lastEtag
	} else if saveSub != nil {
		if saveSub.Content == nil {
			return nil
		}
		err := s.loadFromContent(saveSub.Content)
		if err != nil {
			return err
		}
		s.lastUpdated = saveSub.LastUpdated
		s.lastEtag = saveSub.LastEtag
	}
	return nil
}

func (s *ProviderRemote) loadFromContent(contentRaw []byte) error {
	content, _ := parser.DecodeBase64URLSafe(string(contentRaw))
	firstLine, others := getFirstLine(content)
	if info, ok := parseInfo(firstLine); ok {
		s.subscriptionInfo = info
		content, _ = parser.DecodeBase64URLSafe(others)
	}
	if err := s.updateProviderFromContent(content); err != nil {
		return err
	}
	return nil
}

func pathExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

func (s *ProviderRemote) loopUpdate() {
	if time.Since(s.lastUpdated) < s.updateInterval {
		select {
		case <-s.ctx.Done():
			return
		case <-time.After(time.Until(s.lastUpdated.Add(s.updateInterval))):
			s.updateOnce()
		}
	} else {
		s.updateOnce()
	}
	s.ticker = time.NewTicker(s.updateInterval)
	for {
		runtime.GC()
		select {
		case <-s.ctx.Done():
			return
		case <-s.ticker.C:
			s.updateOnce()
		}
	}
}

func (s *ProviderRemote) saveCacheFile(hasInfo bool, info adapter.SubscriptionInfo, contentRaw []byte) {
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
	s.hash = hash.MakeHash(content)
	dir := filepath.Dir(s.path)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		filemanager.MkdirAll(s.ctx, dir, 0o755)
	}
	filemanager.WriteFile(s.ctx, s.path, []byte(content), 0o666)
}

func (s *ProviderRemote) updateProviderFromContent(content string) error {
	outboundOpts, err := parser.ParseSubscription(s.ctx, content)
	if err != nil {
		return err
	}
	outboundOpts = common.Filter(outboundOpts, func(it option.Outbound) bool {
		return (s.exclude == nil || !s.exclude.MatchString(it.Tag)) && (s.include == nil || s.include.MatchString(it.Tag))
	})
	s.UpdateOutbounds(s.lastOutOpts, outboundOpts)
	s.lastOutOpts = outboundOpts
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
