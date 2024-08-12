package rule

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/hash"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/experimental/deprecated"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/filemanager"
	"github.com/sagernet/sing/service/pause"
)

var _ adapter.RuleSet = (*RemoteRuleSet)(nil)

type RemoteRuleSet struct {
	abstractRuleSet
	cancel         context.CancelFunc
	outbound       adapter.OutboundManager
	url            string
	urlHash        [32]byte
	initialPath    string
	options        option.RemoteRuleSet
	updateInterval time.Duration
	httpClient     *http.Client
	hash           hash.HashType
	lastEtag       string
	cacheFile      adapter.CacheFile
	pauseManager   pause.Manager
	updating       atomic.Bool
}

func NewRemoteRuleSet(ctx context.Context, logger logger.ContextLogger, tag string, options option.RuleSet) (*RemoteRuleSet, error) {
	ctx, cancel := context.WithCancel(ctx)
	if options.Path != "" && options.RemoteOptions.InitialPath != "" {
		cancel()
		return nil, E.New("rule-set path and initial_path are mutually exclusive")
	}
	var path string
	if options.Path != "" {
		path = filemanager.BasePath(ctx, strings.ReplaceAll(options.Path, C.RuleSetTagPlaceholder, tag))
		path, _ = filepath.Abs(path)
	}
	var updateInterval time.Duration
	if options.RemoteOptions.UpdateInterval > 0 {
		updateInterval = time.Duration(options.RemoteOptions.UpdateInterval)
	} else {
		updateInterval = 24 * time.Hour
	}
	var initialPath string
	if options.RemoteOptions.InitialPath != "" {
		initialPath = filemanager.BasePath(ctx, strings.ReplaceAll(options.RemoteOptions.InitialPath, C.RuleSetTagPlaceholder, tag))
		initialPath, _ = filepath.Abs(initialPath)
	}
	url := strings.ReplaceAll(options.RemoteOptions.URL, C.RuleSetTagPlaceholder, tag)
	return &RemoteRuleSet{
		abstractRuleSet: abstractRuleSet{
			ctx:    ctx,
			logger: logger,
			tag:    tag,
			sType:  options.Type,
			path:   path,
			format: options.Format,
		},
		outbound:       service.FromContext[adapter.OutboundManager](ctx),
		url:            url,
		urlHash:        sha256.Sum256([]byte(url)),
		initialPath:    initialPath,
		cancel:         cancel,
		options:        options.RemoteOptions,
		updateInterval: updateInterval,
		pauseManager:   service.FromContext[pause.Manager](ctx),
	}, nil
}

func (s *RemoteRuleSet) StartContext(ctx context.Context, startContext *adapter.HTTPStartContext) error {
	s.cacheFile = service.FromContext[adapter.CacheFile](s.ctx)
	transport, err := s.resolveTransport()
	if err != nil {
		return E.Cause(err, "create rule-set http client")
	}
	startContext.Register(transport)
	s.httpClient = &http.Client{Transport: transport}
	if s.initialPath != "" && s.cacheFile == nil {
		return E.New("rule-set initial_path requires cache_file")
	}
	loadedFromCache, err := s.loadCacheFile()
	if err != nil {
		s.logger.Warn(E.Cause(err, "restore cached rule-set, will refetch"))
	}
	var loadedFromInitialPath bool
	if !loadedFromCache && s.initialPath != "" {
		file, openErr := filemanager.Open(s.ctx, s.initialPath)
		err = openErr
		if err == nil {
			err = s.loadReader(file, s)
			_ = file.Close()
		}
		if err != nil {
			s.logger.Warn(E.Cause(err, "load initial rule-set from ", s.initialPath))
		} else {
			loadedFromInitialPath = true
		}
	}
	if !loadedFromCache && !loadedFromInitialPath {
		err = s.fetch(ctx, true)
		if err != nil {
			return E.Cause(err, "initial rule-set: ", s.tag)
		}
	}
	return nil
}

func (s *RemoteRuleSet) update() {
	ctx := log.ContextWithNewID(s.ctx)
	err := s.fetch(ctx, false)
	if err != nil {
		s.logger.ErrorContext(ctx, "fetch rule-set ", s.tag, ": ", err)
	} else {
		s.Cleanup()
	}
}

func (s *RemoteRuleSet) Update(ctx context.Context) error {
	err := s.fetch(log.ContextWithNewID(ctx), false)
	if err != nil {
		return err
	}
	s.Cleanup()
	return nil
}

func (s *RemoteRuleSet) fetch(ctx context.Context, isStart bool) error {
	if s.updating.Swap(true) {
		return E.New("rule-set is updating")
	}
	defer s.updating.Store(false)
	s.logger.DebugContext(ctx, "updating rule-set ", s.tag, " from URL: ", s.url)
	request, err := http.NewRequest("GET", s.url, nil)
	if err != nil {
		return err
	}
	if s.lastEtag != "" {
		request.Header.Set("If-None-Match", s.lastEtag)
	}
	if !isStart {
		defer s.httpClient.CloseIdleConnections()
	}
	response, err := s.httpClient.Do(request.WithContext(ctx))
	if err != nil {
		return err
	}
	defer response.Body.Close()
	switch response.StatusCode {
	case http.StatusOK:
	case http.StatusNotModified:
		lastUpdated := time.Now()
		s.setUpdatedTime(lastUpdated)
		if s.cacheFile != nil {
			if savedRuleSet := s.cacheFile.LoadRuleSet(s.tag); savedRuleSet != nil {
				savedRuleSet.LastUpdated = lastUpdated
				savedRuleSet.URLHash = s.urlHash[:]
				if err = s.cacheFile.SaveRuleSet(s.tag, savedRuleSet); err != nil {
					s.logger.Error("save rule-set updated time: ", err)
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
		return err
	}
	prepared, err := s.prepareBytes(content)
	if err != nil {
		return err
	}
	if s.path != "" {
		if err = s.saveCacheFile(content); err != nil {
			return E.Cause(err, "save rule-set cache file")
		}
	}
	s.publishContent(prepared, s)
	eTagHeader := response.Header.Get("Etag")
	if eTagHeader != "" {
		s.lastEtag = eTagHeader
	}
	lastUpdated := time.Now()
	s.setUpdatedTime(lastUpdated)
	if s.cacheFile != nil {
		savedRuleSet := &adapter.SavedBinary{
			LastUpdated: lastUpdated,
			LastEtag:    s.lastEtag,
			URLHash:     s.urlHash[:],
		}
		if s.path != "" {
			savedRuleSet.Hash = s.hash
		} else {
			savedRuleSet.Content = content
		}
		if err = s.cacheFile.SaveRuleSet(s.tag, savedRuleSet); err != nil {
			s.logger.Error("save rule-set cache: ", err)
		}
	}
	s.logger.InfoContext(ctx, "updated rule-set ", s.tag)
	return nil
}

func (s *RemoteRuleSet) resolveTransport() (adapter.HTTPTransport, error) {
	httpClientManager := service.FromContext[adapter.HTTPClientManager](s.ctx)
	if s.options.HTTPClient != nil && !s.options.HTTPClient.IsEmpty() {
		if s.options.DownloadDetour != "" { //nolint:staticcheck
			return nil, E.New("http_client conflicts with deprecated download_detour field")
		}
		return httpClientManager.ResolveTransport(s.ctx, s.logger, *s.options.HTTPClient)
	}
	if s.options.DownloadDetour != "" { //nolint:staticcheck
		deprecated.Report(s.ctx, deprecated.OptionLegacyRuleSetDownloadDetour)
		return httpClientManager.ResolveTransport(s.ctx, s.logger, option.HTTPClientOptions{
			DialerOptions: option.DialerOptions{
				Detour: s.options.DownloadDetour, //nolint:staticcheck
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

func (s *RemoteRuleSet) loadCacheFile() (bool, error) {
	var content []byte
	var lastUpdated time.Time
	var lastEtag string
	var savedSet *adapter.SavedBinary
	if s.cacheFile != nil {
		if savedSet = s.cacheFile.LoadRuleSet(s.tag); savedSet != nil {
			if len(savedSet.URLHash) > 0 && !bytes.Equal(savedSet.URLHash, s.urlHash[:]) {
				s.logger.Info("cached rule-set was downloaded from another URL, will refetch")
				return false, nil
			}
			s.hash = savedSet.Hash
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
		defer file.Close()
		info, err := file.Stat()
		if err != nil {
			return false, err
		}
		if savedSet != nil {
			hasher := md5.New()
			if _, err = io.Copy(hasher, file); err != nil {
				return false, err
			}
			if !bytes.Equal(s.hash.Bytes(), hasher.Sum(nil)) {
				return false, E.New("load rule-set cache file failed: validation failed")
			}
			if _, err = file.Seek(0, io.SeekStart); err != nil {
				return false, err
			}
			lastUpdated = savedSet.LastUpdated
			lastEtag = savedSet.LastEtag
		} else {
			lastUpdated = info.ModTime()
		}
		if err = s.loadReader(file, s); err != nil {
			return false, err
		}
		s.lastUpdated, s.lastEtag = lastUpdated, lastEtag
		return true, nil
	} else if savedSet != nil && len(savedSet.Content) > 0 {
		content = savedSet.Content
		lastUpdated = savedSet.LastUpdated
		lastEtag = savedSet.LastEtag
	} else {
		return false, nil
	}
	if err := s.loadBytes(content, s); err != nil {
		return false, err
	}
	s.setUpdatedTime(lastUpdated)
	s.lastEtag = lastEtag
	return true, nil
}

func pathExists(ctx context.Context, path string) (bool, error) {
	info, err := filemanager.Stat(ctx, path)
	if err == nil {
		if info.IsDir() {
			return false, E.New("rule_set path is a directory: ", path)
		}
		return true, nil
	}
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	return false, err
}

func (s *RemoteRuleSet) saveCacheFile(content []byte) error {
	dir := filepath.Dir(s.path)
	err := filemanager.MkdirAll(s.ctx, dir, 0o755)
	if err != nil {
		return err
	}
	targetPath := filemanager.BasePath(s.ctx, s.path)
	lstatInfo, lstatErr := os.Lstat(targetPath)
	if lstatErr == nil && lstatInfo.Mode()&os.ModeSymlink != 0 {
		if err = filemanager.WriteFile(s.ctx, s.path, content, 0o666); err != nil {
			return err
		}
		s.hash = hash.MakeHash(content)
		return nil
	}
	mode := os.FileMode(0o666)
	preserveMode := false
	if lstatErr == nil && lstatInfo.Mode().IsRegular() {
		mode = lstatInfo.Mode().Perm()
		preserveMode = true
	}
	var (
		tmpPath string
		tmpFile *os.File
	)
	baseName := filepath.Base(s.path)
	stamp := time.Now().UnixNano()
	for attempt := 0; attempt < 16; attempt++ {
		candidate := filepath.Join(dir, "."+baseName+"."+strconv.FormatInt(stamp+int64(attempt), 36)+".tmp")
		tmpFile, err = filemanager.OpenFile(s.ctx, candidate, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
		if err == nil {
			tmpPath = candidate
			break
		}
		if !errors.Is(err, os.ErrExist) {
			return err
		}
	}
	if tmpFile == nil {
		return err
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = filemanager.Remove(s.ctx, tmpPath)
		}
	}()
	if preserveMode {
		if err = tmpFile.Chmod(mode); err != nil {
			_ = tmpFile.Close()
			return err
		}
	}
	_, writeErr := tmpFile.Write(content)
	closeErr := tmpFile.Close()
	if writeErr != nil {
		return writeErr
	}
	if closeErr != nil {
		return closeErr
	}
	if err = filemanager.Chown(s.ctx, tmpPath); err != nil {
		return err
	}
	if err = filemanager.Rename(s.ctx, tmpPath, s.path); err != nil {
		return err
	}
	cleanup = false
	s.hash = hash.MakeHash(content)
	return nil
}

func (s *RemoteRuleSet) Close() error {
	s.clearContent()
	s.cancel()
	return nil
}
