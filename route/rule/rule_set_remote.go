package rule

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/hash"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ntp"
	"github.com/sagernet/sing/common/rw"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/filemanager"
	"github.com/sagernet/sing/service/pause"
)

var _ adapter.RuleSet = (*RemoteRuleSet)(nil)

type RemoteRuleSet struct {
	abstractRuleSet
	cancel         context.CancelFunc
	outbound       adapter.OutboundManager
	options        option.RemoteRuleSet
	updateInterval time.Duration
	dialer         N.Dialer
	hash           hash.HashType
	lastEtag       string
	updateTicker   *time.Ticker
	cacheFile      adapter.CacheFile
	pauseManager   pause.Manager
	callbackAccess sync.Mutex
	callbacks      list.List[adapter.RuleSetUpdateCallback]
}

func NewRemoteRuleSet(ctx context.Context, logger logger.ContextLogger, options option.RuleSet) *RemoteRuleSet {
	ctx, cancel := context.WithCancel(ctx)
	var path string
	if options.Path != "" {
		path = filemanager.BasePath(ctx, options.Path)
		path, _ = filepath.Abs(path)
	}
	var updateInterval time.Duration
	if options.RemoteOptions.UpdateInterval > 0 {
		updateInterval = time.Duration(options.RemoteOptions.UpdateInterval)
	} else {
		updateInterval = 24 * time.Hour
	}
	return &RemoteRuleSet{
		abstractRuleSet: abstractRuleSet{
			ctx:    ctx,
			logger: logger,
			tag:    options.Tag,
			path:   path,
			format: options.Format,
		},
		outbound:       service.FromContext[adapter.OutboundManager](ctx),
		cancel:         cancel,
		options:        options.RemoteOptions,
		updateInterval: updateInterval,
		pauseManager:   service.FromContext[pause.Manager](ctx),
	}
}

func (s *RemoteRuleSet) String() string {
	return strings.Join(F.MapToString(s.rules), " ")
}

func (s *RemoteRuleSet) StartContext(ctx context.Context, startContext *adapter.HTTPStartContext) error {
	s.cacheFile = service.FromContext[adapter.CacheFile](s.ctx)
	var dialer N.Dialer
	if s.options.DownloadDetour != "" {
		outbound, loaded := s.outbound.Outbound(s.options.DownloadDetour)
		if !loaded {
			return E.New("download detour not found: ", s.options.DownloadDetour)
		}
		dialer = outbound
	} else {
		dialer = s.outbound.Default()
	}
	s.dialer = dialer
	err := s.loadCacheFile()
	if err != nil {
		return E.Cause(err, "restore cached rule-set")
	}
	if s.lastUpdated.IsZero() {
		err := s.fetch(ctx, startContext)
		if err != nil {
			return E.Cause(err, "initial rule-set: ", s.tag)
		}
	}
	s.updateTicker = time.NewTicker(s.updateInterval)
	return nil
}

func (s *RemoteRuleSet) PostStart() error {
	go s.loopUpdate()
	return nil
}

func (s *RemoteRuleSet) RegisterCallback(callback adapter.RuleSetUpdateCallback) *list.Element[adapter.RuleSetUpdateCallback] {
	s.callbackAccess.Lock()
	defer s.callbackAccess.Unlock()
	return s.callbacks.PushBack(callback)
}

func (s *RemoteRuleSet) UnregisterCallback(element *list.Element[adapter.RuleSetUpdateCallback]) {
	s.callbackAccess.Lock()
	defer s.callbackAccess.Unlock()
	s.callbacks.Remove(element)
}

func (s *RemoteRuleSet) loadBytes(content []byte) error {
	err := s.abstractRuleSet.loadBytes(content)
	if err != nil {
		return err
	}
	s.callbackAccess.Lock()
	callbacks := s.callbacks.Array()
	s.callbackAccess.Unlock()
	for _, callback := range callbacks {
		callback(s)
	}
	return nil
}

func (s *RemoteRuleSet) loopUpdate() {
	if time.Since(s.lastUpdated) > s.updateInterval {
		s.update()
	}
	for {
		runtime.GC()
		select {
		case <-s.ctx.Done():
			return
		case <-s.updateTicker.C:
			s.update()
		}
	}
}

func (s *RemoteRuleSet) update() {
	ctx := log.ContextWithNewID(s.ctx)
	err := s.fetch(ctx, nil)
	if err != nil {
		s.logger.ErrorContext(ctx, "fetch rule-set ", s.tag, ": ", err)
	} else if s.refs.Load() == 0 {
		s.rules = nil
	}
}

func (s *RemoteRuleSet) fetch(ctx context.Context, startContext *adapter.HTTPStartContext) error {
	s.logger.DebugContext(ctx, "updating rule-set ", s.tag, " from URL: ", s.options.URL)
	var httpClient *http.Client
	if startContext != nil {
		httpClient = startContext.HTTPClient(s.options.DownloadDetour, s.dialer)
	} else {
		httpClient = &http.Client{
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
	}
	request, err := http.NewRequest("GET", s.options.URL, nil)
	if err != nil {
		return err
	}
	if s.lastEtag != "" {
		request.Header.Set("If-None-Match", s.lastEtag)
	}
	response, err := httpClient.Do(request.WithContext(ctx))
	if err != nil {
		return err
	}
	switch response.StatusCode {
	case http.StatusOK:
	case http.StatusNotModified:
		s.lastUpdated = time.Now()
		if s.path != "" {
			os.Chtimes(s.path, s.lastUpdated, s.lastUpdated)
		}
		if s.cacheFile != nil {
			if savedRuleSet := s.cacheFile.LoadRuleSet(s.tag); savedRuleSet != nil {
				savedRuleSet.LastUpdated = s.lastUpdated
				err = s.cacheFile.SaveRuleSet(s.tag, savedRuleSet)
				if err != nil {
					s.logger.Error("save rule-set updated time: ", err)
					return nil
				}
			}
		}
		s.logger.InfoContext(ctx, "update rule-set ", s.tag, ": not modified")
		return nil
	default:
		return E.New("unexpected status: ", response.Status)
	}
	content, err := io.ReadAll(response.Body)
	if err != nil {
		response.Body.Close()
		return err
	}
	err = s.loadBytes(content)
	if err != nil {
		response.Body.Close()
		return err
	}
	response.Body.Close()
	eTagHeader := response.Header.Get("Etag")
	if eTagHeader != "" {
		s.lastEtag = eTagHeader
	}
	s.lastUpdated = time.Now()
	if s.path != "" {
		s.saveCacheFile(content)
		if s.cacheFile != nil {
			err = s.cacheFile.SaveRuleSet(s.tag, &adapter.SavedBinary{
				Hash:        s.hash,
				LastUpdated: s.lastUpdated,
				LastEtag:    s.lastEtag,
			})
		}
	} else if s.cacheFile != nil {
		err = s.cacheFile.SaveRuleSet(s.tag, &adapter.SavedBinary{
			LastUpdated: s.lastUpdated,
			Content:     content,
			LastEtag:    s.lastEtag,
		})
	}
	if err != nil {
		s.logger.Error("save rule-set cache: ", err)
	}
	s.logger.InfoContext(ctx, "updated rule-set ", s.tag)
	return nil
}

func (s *RemoteRuleSet) loadCacheFile() error {
	var savedSet *adapter.SavedBinary
	if s.cacheFile != nil {
		if savedSet = s.cacheFile.LoadRuleSet(s.tag); savedSet != nil {
			s.hash = savedSet.Hash
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
		if savedSet != nil {
			hash := hash.MakeHash(content)
			if !s.hash.Equal(hash) {
				s.logger.Error("load rule-set cache file failed: validation failed")
				return nil
			}
			lastUpdated = savedSet.LastUpdated
			lastEtag = savedSet.LastEtag
		} else {
			fs, _ := file.Stat()
			lastUpdated = fs.ModTime()
		}
		err = s.loadBytes(content)
		if err != nil {
			return err
		}
		s.lastUpdated = lastUpdated
		s.lastEtag = lastEtag
	} else if savedSet != nil {
		if savedSet.Content == nil {
			return nil
		}
		err := s.loadBytes(savedSet.Content)
		if err != nil {
			return err
		}
		s.lastUpdated = savedSet.LastUpdated
		s.lastEtag = savedSet.LastEtag
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
	if rw.IsDir(path) {
		return false, E.New("rule_set path is a directory: ", path)
	}
	return false, err
}

func (s *RemoteRuleSet) saveCacheFile(contentRaw []byte) {
	s.hash = hash.MakeHash(contentRaw)
	dir := filepath.Dir(s.path)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		filemanager.MkdirAll(s.ctx, dir, 0o755)
	}
	filemanager.WriteFile(s.ctx, s.path, []byte(contentRaw), 0o666)
}

func (s *RemoteRuleSet) Close() error {
	s.rules = nil
	s.cancel()
	if s.updateTicker != nil {
		s.updateTicker.Stop()
	}
	return nil
}
