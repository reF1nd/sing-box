package route

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/sagernet/fswatch"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/geoip"
	"github.com/sagernet/sing-box/common/geosite"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/experimental/deprecated"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/rw"
	"github.com/sagernet/sing/service/filemanager"
)

func (r *Router) GeoIPReader() *geoip.Reader {
	return r.geoIPReader
}

func (r *Router) LoadGeosite(code string) (adapter.Rule, error) {
	rule, cached := r.geositeCache[code]
	if cached {
		return rule, nil
	}
	items, err := r.geositeReader.Read(code)
	if err != nil {
		return nil, err
	}
	rule, err = NewDefaultRule(r.ctx, r, nil, geosite.Compile(items))
	if err != nil {
		return nil, err
	}
	r.geositeCache[code] = rule
	return rule, nil
}

func (r *Router) prepareGeoIPDatabase() error {
	deprecated.Report(r.ctx, deprecated.OptionGEOIP)
	var geoPath string
	if r.geoIPOptions.Path != "" {
		geoPath = r.geoIPOptions.Path
	} else {
		geoPath = "geoip.db"
		if foundPath, loaded := C.FindPath(geoPath); loaded {
			geoPath = foundPath
		}
	}
	if !rw.IsFile(geoPath) {
		geoPath = filemanager.BasePath(r.ctx, geoPath)
	}
	if stat, err := os.Stat(geoPath); err == nil {
		if stat.IsDir() {
			return E.New("geoip path is a directory: ", geoPath)
		}
		if stat.Size() == 0 {
			os.Remove(geoPath)
		}
	}
	r.geoIPPath = geoPath
	if !rw.IsFile(geoPath) {
		r.logger.Warn("geoip database not exists: ", geoPath)
		var err error
		for attempts := 0; attempts < 3; attempts++ {
			err = r.downloadGeoIPDatabase(geoPath)
			if err == nil {
				break
			}
			r.logger.Error("download geoip database: ", err)
			os.Remove(geoPath)
			// time.Sleep(10 * time.Second)
		}
		if err != nil {
			return err
		}
	}
	geoReader, codes, err := geoip.Open(geoPath)
	if err != nil {
		return E.Cause(err, "open geoip database")
	}
	r.logger.Info("loaded geoip database: ", len(codes), " codes")
	r.geoIPReader = geoReader
	return nil
}

func (r *Router) prepareGeositeDatabase() error {
	deprecated.Report(r.ctx, deprecated.OptionGEOSITE)
	var geoPath string
	if r.geositeOptions.Path != "" {
		geoPath = r.geositeOptions.Path
	} else {
		geoPath = "geosite.db"
		if foundPath, loaded := C.FindPath(geoPath); loaded {
			geoPath = foundPath
		}
	}
	if !rw.IsFile(geoPath) {
		geoPath = filemanager.BasePath(r.ctx, geoPath)
	}
	if stat, err := os.Stat(geoPath); err == nil {
		if stat.IsDir() {
			return E.New("geosite path is a directory: ", geoPath)
		}
		if stat.Size() == 0 {
			os.Remove(geoPath)
		}
	}
	r.geositePath = geoPath
	if !rw.IsFile(geoPath) {
		r.logger.Warn("geosite database not exists: ", geoPath)
		var err error
		for attempts := 0; attempts < 3; attempts++ {
			err = r.downloadGeositeDatabase(geoPath)
			if err == nil {
				break
			}
			r.logger.Error("download geosite database: ", err)
			os.Remove(geoPath)
		}
		if err != nil {
			return err
		}
	}
	geoReader, codes, err := geosite.Open(geoPath)
	if err == nil {
		r.logger.Info("loaded geosite database: ", len(codes), " codes")
		r.geositeReader = geoReader
	} else {
		return E.Cause(err, "open geosite database")
	}
	return nil
}

func (r *Router) loopUpdateGeoIPDatabase() {
	if stat, err := os.Stat(r.geoIPPath); err == nil {
		if time.Since(stat.ModTime()) > time.Duration(r.geoIPOptions.AutoUpdateInterval) {
			r.updateGeoIPDatabase()
		}
	}
	ticker := time.NewTicker(time.Duration(r.geoIPOptions.AutoUpdateInterval))
	defer ticker.Stop()
	for {
		select {
		case <-r.ctx.Done():
			return
		case <-ticker.C:
			r.updateGeoIPDatabase()
		}
	}
}

func (r *Router) updateGeoIPDatabase() {
	if !r.geoIPUpdateLock.TryLock() {
		return
	}
	defer r.geoIPUpdateLock.Unlock()
	r.logger.Info("try to update geoip database...")
	tempGeoPath := r.geoIPPath + ".tmp"
	os.Remove(tempGeoPath)
	err := r.downloadGeoIPDatabase(tempGeoPath)
	if err != nil {
		r.logger.Error("download geoip database failed: ", err)
		return
	}
	r.logger.Info("download geoip database success")
	geoReader, codes, err := geoip.Open(tempGeoPath)
	if err != nil {
		r.logger.Error(E.Cause(err, "open geoip database"))
		os.Remove(tempGeoPath)
		return
	}
	err = os.Rename(tempGeoPath, r.geoIPPath)
	if err != nil {
		r.logger.Error("save geoip database failed: ", err)
		os.Remove(tempGeoPath)
		return
	}
	r.logger.Info("loaded geoip database: ", len(codes), " codes")
	r.geoIPReader = geoReader
	r.logger.Info("reload geoip database success")
}

func (r *Router) loadGeoIPDatabase(geoPath string) error {
	geoReader, codes, err := geoip.Open(geoPath)
	if err != nil {
		err = E.Cause(err, "open geoip database")
		return err
	}
	r.logger.Info("loaded geoip database: ", len(codes), " codes")
	r.geoIPReader = geoReader
	return nil
}

func (r *Router) loopUpdateGeositeDatabase() {
	if stat, err := os.Stat(r.geositePath); err == nil {
		if time.Since(stat.ModTime()) > time.Duration(r.geositeOptions.AutoUpdateInterval) {
			r.updateGeositeDatabase()
		}
	}
	ticker := time.NewTicker(time.Duration(r.geositeOptions.AutoUpdateInterval))
	defer ticker.Stop()
	for {
		select {
		case <-r.ctx.Done():
			return
		case <-ticker.C:
			r.updateGeositeDatabase()
		}
	}
}

func (r *Router) updateGeositeDatabase() {
	if !r.geositeUpdateLock.TryLock() {
		return
	}
	defer r.geositeUpdateLock.Unlock()
	r.logger.Info("try to update geosite database...")
	tempGeoPath := r.geositePath + ".tmp"
	os.Remove(tempGeoPath)
	err := r.downloadGeositeDatabase(tempGeoPath)
	if err != nil {
		r.logger.Error("download geosite database failed: ", err)
		return
	}
	r.logger.Info("download geosite database success")
	geoReader, codes, err := geosite.Open(tempGeoPath)
	if err != nil {
		r.logger.Error(E.Cause(err, "open geosite database"))
		return
	}
	r.logger.Info("loaded geosite database: ", len(codes), " codes")
	r.geositeReader = geoReader
	r.geositeCache = make(map[string]adapter.Rule)
	for _, rule := range r.rules {
		err := rule.UpdateGeosite()
		if err != nil {
			r.logger.Error("failed to reload geosite rules: ", err)
		}
	}
	for _, rule := range r.dnsRules {
		err := rule.UpdateGeosite()
		if err != nil {
			r.logger.Error("failed to reload geosite rules: ", err)
		}
	}
	err = common.Close(r.geositeReader)
	if err != nil {
		r.logger.Error("close geosite reader failed: ", err)
	}
	r.geositeCache = nil
	r.geositeReader = nil
	err = os.Rename(tempGeoPath, r.geositePath)
	if err != nil {
		r.logger.Error("save geosite database failed: ", err)
		os.Remove(tempGeoPath)
		return
	}
	r.logger.Info("reload geosite rules success")
}

func (r *Router) loadGeositeDatabase(geoPath string) error {
	geoReader, codes, err := geosite.Open(geoPath)
	if err != nil {
		return E.Cause(err, "open geosite database")
	}
	r.logger.Info("loaded geosite database: ", len(codes), " codes")
	r.geositeReader = geoReader
	return nil
}

func (r *Router) loadGeositeRule() {
	r.geositeCache = make(map[string]adapter.Rule)
	for _, rule := range r.rules {
		err := rule.UpdateGeosite()
		if err != nil {
			r.logger.Error("failed to initialize geosite: ", err)
		}
	}
	for _, rule := range r.dnsRules {
		err := rule.UpdateGeosite()
		if err != nil {
			r.logger.Error("failed to initialize geosite: ", err)
		}
	}
	err := common.Close(r.geositeReader)
	if err != nil {
		r.logger.Error("close geosite reader: ", err)
	}
	r.geositeCache = nil
	r.geositeReader = nil
}

func (r *Router) UpdateGeoDatabase() {
	if !r.geoUpdateLock.TryLock() {
		return
	}
	defer r.geoUpdateLock.Unlock()
	if r.needGeositeDatabase {
		r.updateGeositeDatabase()
	}
	if r.needGeoIPDatabase {
		r.updateGeoIPDatabase()
	}
}

func (r *Router) geoUpdated(path string) error {
	if path == r.geoIPPath || path == r.geositePath {
		if path == r.geoIPPath {
			err := r.loadGeoIPDatabase(r.geoIPPath)
			if err != nil {
				return err
			}
		} else {
			err := r.loadGeositeDatabase(r.geositePath)
			if err != nil {
				return err
			}
			r.loadGeositeRule()
		}
	}
	return nil
}

func (r *Router) startGeoWatcher() error {
	var watchPath []string
	if r.needGeoIPDatabase {
		watchPath = append(watchPath, r.geoIPPath)
		r.logger.Debug("geo resource watcher: watching ", r.geoIPPath)
	}
	if r.needGeositeDatabase {
		watchPath = append(watchPath, r.geositePath)
		r.logger.Debug("geo resource watcher: watching ", r.geositePath)
	}
	geoWatcher, err := fswatch.NewWatcher(fswatch.Options{
		Path: watchPath,
		Callback: func(path string) {
			err := r.geoUpdated(path)
			if err != nil {
				r.logger.Error(E.Cause(err, "reload geodatabase from ", path))
			}
		},
	})
	if err != nil {
		return err
	}
	r.geoWatcher = geoWatcher
	r.logger.Debug("geo resource watcher started")
	return nil
}

func (r *Router) downloadGeoIPDatabase(savePath string) error {
	var downloadURL string
	if r.geoIPOptions.DownloadURL != "" {
		downloadURL = r.geoIPOptions.DownloadURL
	} else {
		downloadURL = "https://github.com/SagerNet/sing-geoip/releases/latest/download/geoip.db"
	}
	r.logger.Info("downloading geoip database")
	var detour adapter.Outbound
	if r.geoIPOptions.DownloadDetour != "" {
		outbound, loaded := r.Outbound(r.geoIPOptions.DownloadDetour)
		if !loaded {
			return E.New("detour outbound not found: ", r.geoIPOptions.DownloadDetour)
		}
		detour = outbound
	} else {
		detour = r.defaultOutboundForConnection
	}

	if parentDir := filepath.Dir(savePath); parentDir != "" {
		filemanager.MkdirAll(r.ctx, parentDir, 0o755)
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			ForceAttemptHTTP2:   true,
			TLSHandshakeTimeout: C.TCPTimeout,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return detour.DialContext(ctx, network, M.ParseSocksaddr(addr))
			},
		},
	}
	defer httpClient.CloseIdleConnections()
	request, err := http.NewRequest("GET", downloadURL, nil)
	if err != nil {
		return err
	}
	response, err := httpClient.Do(request.WithContext(r.ctx))
	if err != nil {
		return err
	}
	defer response.Body.Close()

	saveFile, err := filemanager.Create(r.ctx, savePath)
	if err != nil {
		return E.Cause(err, "open output file: ", downloadURL)
	}
	_, err = io.Copy(saveFile, response.Body)
	saveFile.Close()
	if err != nil {
		filemanager.Remove(r.ctx, savePath)
	}
	return err
}

func (r *Router) downloadGeositeDatabase(savePath string) error {
	var downloadURL string
	if r.geositeOptions.DownloadURL != "" {
		downloadURL = r.geositeOptions.DownloadURL
	} else {
		downloadURL = "https://github.com/SagerNet/sing-geosite/releases/latest/download/geosite.db"
	}
	r.logger.Info("downloading geosite database")
	var detour adapter.Outbound
	if r.geositeOptions.DownloadDetour != "" {
		outbound, loaded := r.Outbound(r.geositeOptions.DownloadDetour)
		if !loaded {
			return E.New("detour outbound not found: ", r.geositeOptions.DownloadDetour)
		}
		detour = outbound
	} else {
		detour = r.defaultOutboundForConnection
	}

	if parentDir := filepath.Dir(savePath); parentDir != "" {
		filemanager.MkdirAll(r.ctx, parentDir, 0o755)
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			ForceAttemptHTTP2:   true,
			TLSHandshakeTimeout: C.TCPTimeout,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return detour.DialContext(ctx, network, M.ParseSocksaddr(addr))
			},
		},
	}
	defer httpClient.CloseIdleConnections()
	request, err := http.NewRequest("GET", downloadURL, nil)
	if err != nil {
		return err
	}
	response, err := httpClient.Do(request.WithContext(r.ctx))
	if err != nil {
		return err
	}
	defer response.Body.Close()

	saveFile, err := filemanager.Create(r.ctx, savePath)
	if err != nil {
		return E.Cause(err, "open output file: ", downloadURL)
	}
	_, err = io.Copy(saveFile, response.Body)
	saveFile.Close()
	if err != nil {
		filemanager.Remove(r.ctx, savePath)
	}
	return err
}
