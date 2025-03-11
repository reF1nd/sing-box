package remote

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/provider"
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
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"
)

func RegisterProvider(registry *provider.Registry) {
	provider.Register[option.ProviderRemoteOptions](registry, C.ProviderTypeRemote, NewProviderRemote)
}

var (
	_ adapter.Provider = (*ProviderRemote)(nil)
	_ adapter.Service  = (*ProviderRemote)(nil)
)

type ProviderRemote struct {
	provider.Adapter
	ctx          context.Context
	cancel       context.CancelFunc
	logger       log.ContextLogger
	outbound     adapter.OutboundManager
	provider     adapter.ProviderManager
	pauseManager pause.Manager
	cacheFile    adapter.CacheFile
	dialer       N.Dialer
	lastEtag     string
	lastOutOpts  []option.Outbound
	lastUpdated  time.Time
	subInfo      adapter.SubInfo
	ticker       *time.Ticker
	updating     atomic.Bool

	url            string
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
	updateInterval := time.Duration(options.UpdateInterval)
	if updateInterval <= 0 {
		updateInterval = 24 * time.Hour
	}
	if updateInterval < time.Minute {
		updateInterval = time.Minute
	}
	var userAgent string
	if options.UserAgent == "" {
		userAgent = "sing-box " + C.Version
	} else {
		userAgent = options.UserAgent
	}
	ctx, cancel := context.WithCancel(ctx)
	outbound := service.FromContext[adapter.OutboundManager](ctx)
	pauseManager := service.FromContext[pause.Manager](ctx)
	logger := logFactory.NewLogger(F.ToString("provider/remote", "[", tag, "]"))
	return &ProviderRemote{
		Adapter:      provider.NewAdapter(ctx, router, outbound, pauseManager, logFactory, logger, tag, C.ProviderTypeRemote, options.HealthCheck),
		ctx:          ctx,
		cancel:       cancel,
		logger:       logger,
		outbound:     outbound,
		provider:     service.FromContext[adapter.ProviderManager](ctx),
		pauseManager: pauseManager,
		subInfo:      adapter.SubInfo{},

		url:            options.URL,
		userAgent:      userAgent,
		downloadDetour: options.DownloadDetour,
		updateInterval: updateInterval,
		exclude:        (*regexp.Regexp)(options.Exclude),
		include:        (*regexp.Regexp)(options.Include),
	}, nil
}

func (s *ProviderRemote) Start() error {
	s.cacheFile = service.FromContext[adapter.CacheFile](s.ctx)
	if s.cacheFile != nil {
		if saveSub := s.cacheFile.LoadSubscription(s.Tag()); saveSub != nil {
			content, _ := parser.DecodeBase64URLSafe(string(saveSub.Content))
			firstLine, others := getFirstLine(content)
			if info, ok := parseInfo(firstLine); ok {
				s.subInfo = info
				content, _ = parser.DecodeBase64URLSafe(others)
			}
			if err := s.updateProviderFromContent(content); err != nil {
				return E.Cause(err, "restore cached outbound provider")
			}
			s.lastUpdated = saveSub.LastUpdated
			s.lastEtag = saveSub.LastEtag
		}
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
	if err := s.fetchOnce(s.ctx); err != nil {
		return E.New("fetch outbound provider ", s.Tag(), ": ", err)
	}
	return nil
}

func (s *ProviderRemote) UpdatedAt() time.Time {
	return s.lastUpdated
}

func (s *ProviderRemote) SubInfo() adapter.SubInfo {
	return s.subInfo
}

func (s *ProviderRemote) Close() error {
	s.cancel()
	if s.ticker != nil {
		s.ticker.Stop()
	}
	return common.Close(&s.Adapter)
}

func (s *ProviderRemote) fetchOnce(ctx context.Context) error {
	if s.updating.Swap(true) {
		return E.New("provider is updating")
	}
	done, ok := s.provider.AddUpdateTask(s.Tag())
	defer func() {
		s.updating.Store(false)
		if ok {
			done()
		}
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
				Time:    ntp.TimeFuncFromContext(s.ctx),
				RootCAs: adapter.RootPoolFromContext(s.ctx),
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
		s.lastUpdated = time.Now()
		if s.cacheFile != nil {
			saveSub := s.cacheFile.LoadSubscription(s.Tag())
			if saveSub != nil {
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
				}
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
	s.subInfo = info
	s.lastUpdated = time.Now()
	if s.cacheFile != nil {
		content, _ := json.Marshal(option.Options{
			Outbounds: s.lastOutOpts,
		})
		if hasInfo {
			content = append([]byte(infoStr+"\n"), content...)
		}
		err = s.cacheFile.SaveSubscription(s.Tag(), &adapter.SavedBinary{
			LastUpdated: s.lastUpdated,
			Content:     content,
			LastEtag:    s.lastEtag,
		})
		if err != nil {
			s.logger.Error("save outbound provider cache file: ", err)
		}
	}
	s.logger.Info("updated outbound provider ", s.Tag())
	return nil
}

func (s *ProviderRemote) loopUpdate() {
	var err error
	s.ticker = time.NewTicker(s.updateInterval)
	if time.Since(s.lastUpdated) < s.updateInterval {
		select {
		case <-s.ctx.Done():
			return
		case <-time.After(time.Until(s.lastUpdated.Add(s.updateInterval))):
			s.pauseManager.WaitActive()
			err = s.fetchOnce(s.ctx)
			if err == nil {
				s.ticker.Reset(s.updateInterval)
			}
		}
	} else {
		err = s.fetchOnce(s.ctx)
	}
	for {
		if err != nil {
			s.logger.Error("fetch outbound provider ", s.Tag(), ": ", err)
		}
		runtime.GC()
		select {
		case <-s.ctx.Done():
			return
		case <-s.ticker.C:
			s.pauseManager.WaitActive()
			err = s.fetchOnce(s.ctx)
		}
	}
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
	s.UpdateGroups()
	return nil
}

func convertToBytes(sizeStr string) int64 {
	sizeStr = strings.TrimSpace(sizeStr)
	if value, err := strconv.ParseInt(sizeStr, 10, 64); err == nil {
		return value
	}
	var unit string
	var value float64
	_, err := fmt.Sscanf(sizeStr, "%f%s", &value, &unit)
	if err != nil {
		return 0
	}

	switch unit {
	case "TB":
		return int64(value * 1024 * 1024 * 1024 * 1024)
	case "GB":
		return int64(value * 1024 * 1024 * 1024)
	case "MB":
		return int64(value * 1024 * 1024)
	case "KB":
		return int64(value * 1024)
	default:
		return 0
	}
}

func convertToUnix(expire string) int64 {
	expire = strings.TrimSpace(expire)
	if value, err := strconv.ParseInt(expire, 10, 64); err == nil {
		return value
	}
	t, err := time.Parse("2006-01-02", expire)
	if err != nil {
		return 0
	}
	return t.Unix()
}

func getFirstLine(content string) (string, string) {
	lines := strings.Split(content, "\n")
	if len(lines) == 1 {
		return lines[0], ""
	}
	others := strings.Join(lines[1:], "\n")
	return lines[0], others
}

func parseInfo(infoStr string) (adapter.SubInfo, bool) {
	info := adapter.SubInfo{}
	if infoStr == "" {
		return info, false
	}
	reg := regexp.MustCompile(`(upload|download|total|expire)[\s\t]*=[\s\t]*(\d*);?`)
	matches := reg.FindAllStringSubmatch(infoStr, 4)
	if len(matches) == 0 {
		return info, false
	}
	for _, match := range matches {
		key, value := match[1], match[2]
		switch key {
		case "upload":
			info.Upload = convertToBytes(value)
		case "download":
			info.Download = convertToBytes(value)
		case "total":
			info.Total = convertToBytes(value)
		case "expire":
			info.Expire = convertToUnix(value)
		default:
			return info, false
		}
	}
	return info, true
}
