package clashapi

import (
	"archive/zip"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/ntp"
	"github.com/sagernet/sing/service/filemanager"
)

func (s *Server) checkAndDownloadExternalUI(update bool) error {
	if s.externalUI == "" {
		return nil
	}
	entries, err := os.ReadDir(s.externalUI)
	if err != nil {
		filemanager.MkdirAll(s.ctx, s.externalUI, 0o755)
	}
	if len(entries) != 0 && s.lastUpdated.IsZero() {
		info, _ := os.Stat(s.externalUI)
		s.lastUpdated = info.ModTime()
	}
	if len(entries) == 0 || update {
		if len(entries) == 0 && s.lastEtag != "" {
			s.lastEtag = ""
		}
		err = s.downloadExternalUI()
		if err != nil {
			s.logger.Error("download external UI error: ", err)
			return err
		}
	}
	return nil
}

func (s *Server) downloadExternalUI() error {
	var downloadURL string
	if s.externalUIDownloadURL != "" {
		downloadURL = s.externalUIDownloadURL
	} else {
		downloadURL = "https://github.com/MetaCubeX/Yacd-meta/archive/gh-pages.zip"
	}
	var detour adapter.Outbound
	if s.externalUIDownloadDetour != "" {
		outbound, loaded := s.outbound.Outbound(s.externalUIDownloadDetour)
		if !loaded {
			return E.New("detour outbound not found: ", s.externalUIDownloadDetour)
		}
		detour = outbound
	} else {
		outbound := s.outbound.Default()
		detour = outbound
	}
	s.logger.Info("downloading external UI using outbound/", detour.Type(), "[", detour.Tag(), "]")
	httpClient := &http.Client{
		Transport: &http.Transport{
			ForceAttemptHTTP2:   true,
			TLSHandshakeTimeout: C.TCPTimeout,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return detour.DialContext(ctx, network, M.ParseSocksaddr(addr))
			},
			TLSClientConfig: &tls.Config{
				Time:    ntp.TimeFuncFromContext(s.ctx),
				RootCAs: adapter.RootPoolFromContext(s.ctx),
			},
		},
	}
	request, err := http.NewRequest("GET", downloadURL, nil)
	if err != nil {
		return err
	}
	if s.lastEtag != "" {
		request.Header.Set("If-None-Match", s.lastEtag)
	}
	response, err := httpClient.Do(request.WithContext(s.ctx))
	if err != nil {
		return err
	}
	switch response.StatusCode {
	case http.StatusOK:
	case http.StatusNotModified:
		s.lastUpdated = time.Now()
		os.Chtimes(s.externalUI, s.lastUpdated, s.lastUpdated)
		if s.cacheFile != nil {
			if savedExternalUI := s.cacheFile.LoadExternalUI("ExternalUI"); savedExternalUI != nil {
				savedExternalUI.LastUpdated = s.lastUpdated
				err = s.cacheFile.SaveExternalUI("ExternalUI", savedExternalUI)
				if err != nil {
					s.logger.Error("save external UI updated time: ", err)
					return nil
				}
			}
		}
		s.logger.Info("update external UI: not modified")
		return nil
	default:
		return E.New("download external UI failed: ", response.Status)
	}
	defer response.Body.Close()
	removeAllInDirectory(s.ctx, s.externalUI)
	err = s.downloadZIP(response.Body, s.externalUI)
	if err != nil {
		removeAllInDirectory(s.ctx, s.externalUI)
		return err
	}
	eTagHeader := response.Header.Get("Etag")
	if eTagHeader != "" {
		s.lastEtag = eTagHeader
	}
	s.lastUpdated = time.Now()
	if s.cacheFile != nil {
		err = s.cacheFile.SaveExternalUI("ExternalUI", &adapter.SavedBinary{
			LastEtag:    s.lastEtag,
			LastUpdated: s.lastUpdated,
		})
		if err != nil {
			s.logger.Error("save external UI cache file: ", err)
		}
	}
	s.logger.Info("updated external UI")
	return nil
}

func (s *Server) downloadZIP(body io.Reader, output string) error {
	tempFile, err := filemanager.CreateTemp(s.ctx, "external-ui.zip")
	if err != nil {
		return err
	}
	defer filemanager.Remove(s.ctx, tempFile.Name())
	_, err = io.Copy(tempFile, body)
	tempFile.Close()
	if err != nil {
		return err
	}
	reader, err := zip.OpenReader(tempFile.Name())
	if err != nil {
		return err
	}
	defer reader.Close()
	trimDir := zipIsInSingleDirectory(reader.File)
	for _, file := range reader.File {
		if file.FileInfo().IsDir() {
			continue
		}
		pathElements := strings.Split(file.Name, "/")
		if trimDir {
			pathElements = pathElements[1:]
		}
		saveDirectory := output
		if len(pathElements) > 1 {
			saveDirectory = filepath.Join(saveDirectory, filepath.Join(pathElements[:len(pathElements)-1]...))
		}
		err = filemanager.MkdirAll(s.ctx, saveDirectory, 0o755)
		if err != nil {
			return err
		}
		savePath := filepath.Join(saveDirectory, pathElements[len(pathElements)-1])
		err = downloadZIPEntry(s.ctx, file, savePath)
		if err != nil {
			return err
		}
	}
	return nil
}

func downloadZIPEntry(ctx context.Context, zipFile *zip.File, savePath string) error {
	saveFile, err := filemanager.Create(ctx, savePath)
	if err != nil {
		return err
	}
	defer saveFile.Close()
	reader, err := zipFile.Open()
	if err != nil {
		return err
	}
	defer reader.Close()
	return common.Error(io.Copy(saveFile, reader))
}

func removeAllInDirectory(ctx context.Context, directory string) {
	dirEntries, err := os.ReadDir(directory)
	if err != nil {
		return
	}
	for _, dirEntry := range dirEntries {
		filemanager.RemoveAll(ctx, filepath.Join(directory, dirEntry.Name()))
	}
}

func zipIsInSingleDirectory(files []*zip.File) bool {
	var singleDirectory string
	for _, file := range files {
		if file.FileInfo().IsDir() {
			continue
		}
		pathElements := strings.Split(file.Name, "/")
		if len(pathElements) == 0 {
			return false
		}
		if singleDirectory == "" {
			singleDirectory = pathElements[0]
		} else if singleDirectory != pathElements[0] {
			return false
		}
	}
	return true
}
