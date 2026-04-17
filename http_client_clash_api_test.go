//go:build with_clash_api

package box_test

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/experimental/deprecated"

	"github.com/stretchr/testify/require"
)

func TestExternalUIHTTPClientValidation(t *testing.T) {
	for _, testCase := range []struct {
		name, clientFields, errorText string
		controller, ui, legacyWarning bool
	}{
		{name: "unused legacy field", clientFields: `"external_ui_download_detour":"direct"`, controller: true},
		{name: "disabled controller", clientFields: `"external_ui_download_detour":"direct"`, ui: true},
		{name: "cached conflict", clientFields: `"external_ui_http_client":"chosen","external_ui_download_detour":"direct"`, controller: true, ui: true, errorText: "external_ui_http_client conflicts with deprecated external_ui_download_detour field"},
		{name: "cached missing tag", clientFields: `"external_ui_http_client":"missing"`, controller: true, ui: true, errorText: "http_client not found: missing"},
		{name: "cached legacy field", clientFields: `"external_ui_download_detour":"direct"`, controller: true, ui: true, legacyWarning: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			dir := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(dir, "index.html"), []byte("cached"), 0600))
			fields := testCase.clientFields
			if testCase.controller {
				fields += `,"external_controller":"127.0.0.1:0"`
			}
			if testCase.ui {
				fields += fmt.Sprintf(`,"external_ui":%q`, dir)
			}
			instance, _, reports := newHTTPClientTestBox(t, fmt.Sprintf(`{
    "log":{"disabled":true},"dns":{"servers":[{"type":"local","tag":"dns"}]},
    "outbounds":[{"type":"direct","tag":"direct"}],
    "http_clients":[{"tag":"chosen","domain_resolver":"dns"}],
    "experimental":{"clash_api":{%s}}
   }`, fields))
			err := instance.Start()
			if testCase.errorText != "" {
				require.ErrorContains(t, err, testCase.errorText)
			} else {
				require.NoError(t, err)
			}
			if testCase.legacyWarning {
				require.Equal(t, []string{deprecated.OptionLegacyClashAPIExternalUIDownloadDetour.Name}, reports.snapshot())
			} else {
				require.Empty(t, reports.snapshot())
			}
		})
	}
}

func TestExternalUIHTTPClientDownloads(t *testing.T) {
	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	entry, err := writer.Create("dashboard/index.html")
	require.NoError(t, err)
	_, err = io.WriteString(entry, "dashboard")
	require.NoError(t, err)
	require.NoError(t, writer.Close())
	for _, mode := range []string{"default", "reference", "inline", "network failure"} {
		t.Run(mode, func(t *testing.T) {
			var access sync.Mutex
			var headers []string
			download := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				access.Lock()
				headers = append(headers, r.Header.Get("X-Client"))
				access.Unlock()
				if mode == "network failure" {
					w.WriteHeader(http.StatusServiceUnavailable)
					return
				}
				_, _ = w.Write(archive.Bytes())
			}))
			defer download.Close()
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			controller := listener.Addr().String()
			require.NoError(t, listener.Close())
			clientFields := ""
			if mode == "reference" {
				clientFields = `,"external_ui_http_client":"chosen"`
			}
			if mode == "inline" {
				clientFields = `,"external_ui_http_client":{"domain_resolver":"dns","headers":{"X-Client":"chosen"}}`
			}
			dir := filepath.Join(t.TempDir(), "ui")
			instance, _, reports := newHTTPClientTestBox(t, fmt.Sprintf(`{
    "log":{"disabled":true},"dns":{"servers":[{"type":"local","tag":"dns"}]},
    "http_clients":[{"tag":"first","domain_resolver":"dns","headers":{"X-Client":"wrong"}},{"tag":"chosen","domain_resolver":"dns","headers":{"X-Client":"chosen"}}],
    "route":{"default_http_client":"chosen"},
    "experimental":{"clash_api":{"external_controller":%q,"external_ui":%q,"external_ui_download_url":%q%s}}
   }`, controller, dir, download.URL, clientFields))
			require.NoError(t, instance.Start())
			if mode == "network failure" {
				require.Empty(t, reports.snapshot())
				return
			}
			data, err := os.ReadFile(filepath.Join(dir, "index.html"))
			require.NoError(t, err)
			require.Equal(t, "dashboard", string(data))
			client := &http.Client{Timeout: 5 * time.Second}
			response, err := client.Post("http://"+controller+"/upgrade/ui", "application/json", nil)
			require.NoError(t, err)
			require.NoError(t, response.Body.Close())
			require.Equal(t, http.StatusOK, response.StatusCode)
			access.Lock()
			require.Equal(t, []string{"chosen", "chosen"}, headers)
			access.Unlock()
			require.Empty(t, reports.snapshot())
		})
	}
}
