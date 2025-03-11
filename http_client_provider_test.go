package box_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

func TestProviderHTTPClientDownloads(t *testing.T) {
	for _, mode := range []string{"default", "reference", "inline"} {
		t.Run(mode, func(t *testing.T) {
			var access sync.Mutex
			var headers []string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				access.Lock()
				headers = append(headers, r.Header.Get("User-Agent"))
				access.Unlock()
				_, _ = io.WriteString(w, `{"outbounds":[{"type":"socks","tag":"node","server":"127.0.0.1","server_port":9}]}`)
			}))
			defer server.Close()
			fields := `,"user_agent":"provider-agent"`
			if mode == "reference" {
				fields = `,"http_client":"chosen"`
			}
			if mode == "inline" {
				fields = `,"http_client":{"domain_resolver":"dns","headers":{"User-Agent":"client-agent"}}`
			}
			instance, ctx, reports := newHTTPClientTestBox(t, fmt.Sprintf(`{
    "log":{"disabled":true},"dns":{"servers":[{"type":"local","tag":"dns"}]},
    "http_clients":[{"tag":"first","domain_resolver":"dns","headers":{"User-Agent":"wrong"}},
                    {"tag":"chosen","domain_resolver":"dns","headers":{"User-Agent":"client-agent"}}],
    "route":{"default_http_client":"chosen"},
    "providers":[{"type":"remote","tag":"p","url":%q%s}]
   }`, server.URL, fields))
			require.NoError(t, instance.Start())
			provider, found := service.FromContext[adapter.ProviderManager](ctx).Get("p")
			require.True(t, found)
			require.NoError(t, provider.(interface{ Update() error }).Update())
			access.Lock()
			require.Equal(t, []string{"client-agent", "client-agent"}, headers)
			access.Unlock()
			require.Empty(t, reports.snapshot())
		})
	}
}

func TestProviderHTTPClientConflicts(t *testing.T) {
	for _, testCase := range []struct{ name, fields, errorText string }{
		{"user agent", `"user_agent":"custom","http_client":"chosen"`, "user_agent conflicts with http_client"},
		{"download detour", `"download_detour":"direct","http_client":"chosen"`, "http_client conflicts with deprecated download_detour field"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			ctx := include.Context(context.Background())
			config := fmt.Sprintf(`{"log":{"disabled":true},"dns":{"servers":[{"type":"local","tag":"dns"}]},"http_clients":[{"tag":"chosen","domain_resolver":"dns"}],"providers":[{"type":"remote","tag":"p","url":"http://127.0.0.1:1/provider",%s}]}`, testCase.fields)
			options, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(config))
			require.NoError(t, err)
			instance, err := box.New(box.Options{Context: ctx, Options: options})
			if err == nil {
				defer instance.Close()
				err = instance.Start()
			}
			require.ErrorContains(t, err, testCase.errorText)
		})
	}
}
