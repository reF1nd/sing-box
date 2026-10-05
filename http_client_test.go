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
	"github.com/sagernet/sing-box/experimental/deprecated"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

type httpClientDeprecations struct {
	access sync.Mutex
	names  []string
}

func (d *httpClientDeprecations) ReportDeprecated(note deprecated.Note) {
	d.access.Lock()
	defer d.access.Unlock()
	d.names = append(d.names, note.Name)
}

func (d *httpClientDeprecations) snapshot() []string {
	d.access.Lock()
	defer d.access.Unlock()
	return append([]string(nil), d.names...)
}

func newHTTPClientTestBox(t *testing.T, config string) (*box.Box, context.Context, *httpClientDeprecations) {
	t.Helper()
	reports := &httpClientDeprecations{}
	ctx := service.ContextWith[deprecated.Manager](include.Context(context.Background()), reports)
	options, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(config))
	require.NoError(t, err)
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, instance.Close()) })
	return instance, ctx, reports
}

func TestDefaultHTTPClientBeforeStart(t *testing.T) {
	for _, defaultTag := range []string{"", "chosen"} {
		t.Run("default="+defaultTag, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, r.Header.Get("X-Client")) }))
			defer server.Close()
			instance, ctx, reports := newHTTPClientTestBox(t, fmt.Sprintf(`{
    "log":{"disabled":true}, "dns":{"servers":[{"type":"local","tag":"dns"}]},
    "http_clients":[{"tag":"first","domain_resolver":"dns","headers":{"X-Client":"first"}},
                    {"tag":"chosen","domain_resolver":"dns","headers":{"X-Client":"chosen"}}],
    "route":{"default_http_client":%q}
   }`, defaultTag))
			manager := service.FromContext[adapter.HTTPClientManager](ctx)
			early := manager.DefaultTransport()
			require.NotNil(t, early)
			require.Empty(t, reports.snapshot())
			// Starting concurrently with lookups must not race or replace the selected transport.
			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				for range 20 {
					manager.DefaultTransport()
				}
			}()
			err := instance.Start()
			wg.Wait()
			require.NoError(t, err)
			expected := defaultTag
			if expected == "" {
				expected = "first"
			}
			for _, transport := range []adapter.HTTPTransport{early, manager.DefaultTransport()} {
				client := &http.Client{Transport: transport}
				response, err := client.Get(server.URL)
				require.NoError(t, err)
				body, err := io.ReadAll(response.Body)
				require.NoError(t, response.Body.Close())
				client.CloseIdleConnections()
				require.NoError(t, err)
				require.Equal(t, expected, string(body))
			}
			require.Empty(t, reports.snapshot())
		})
	}
}

func TestInvalidDefaultHTTPClientNeverFallsBack(t *testing.T) {
	for _, testCase := range []struct{ name, clients, errorText string }{
		{"missing tag", `[]`, "http_client not found: missing"},
		{"invalid client", `[{"tag":"missing","domain_resolver":"dns","engine":"invalid"}]`, "unknown HTTP engine"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			instance, ctx, reports := newHTTPClientTestBox(t, fmt.Sprintf(`{"log":{"disabled":true},"dns":{"servers":[{"type":"local","tag":"dns"}]},"http_clients":%s,"route":{"default_http_client":"missing"}}`, testCase.clients))
			require.Nil(t, service.FromContext[adapter.HTTPClientManager](ctx).DefaultTransport())
			require.Empty(t, reports.snapshot())
			require.ErrorContains(t, instance.Start(), testCase.errorText)
			require.Empty(t, reports.snapshot())
		})
	}
}

func TestImplicitHTTPClientRemainsLazy(t *testing.T) {
	instance, ctx, reports := newHTTPClientTestBox(t, `{"log":{"disabled":true}}`)
	require.NoError(t, instance.Start())
	require.Empty(t, reports.snapshot())
	manager := service.FromContext[adapter.HTTPClientManager](ctx)
	require.NotNil(t, manager.DefaultTransport())
	require.NotNil(t, manager.DefaultTransport())
	require.Equal(t, []string{deprecated.OptionImplicitDefaultHTTPClient.Name}, reports.snapshot())
}

func TestRemoteRuleSetDefaultHTTPClient(t *testing.T) {
	var access sync.Mutex
	var headers []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		access.Lock()
		headers = append(headers, r.Header.Get("X-Client"))
		access.Unlock()
		_, _ = io.WriteString(w, `{"version":3,"rules":[{"domain":"example.com"}]}`)
	}))
	defer server.Close()
	instance, _, reports := newHTTPClientTestBox(t, fmt.Sprintf(`{
  "log":{"disabled":true},"dns":{"servers":[{"type":"local","tag":"dns"}]},
  "http_clients":[{"tag":"chosen","domain_resolver":"dns","headers":{"X-Client":"chosen"}}],
  "route":{"default_http_client":"chosen","rule_set":[{"type":"remote","tag":"r","format":"source","url":%q}]}
 }`, server.URL))
	require.NoError(t, instance.Start())
	access.Lock()
	require.Equal(t, []string{"chosen"}, headers)
	access.Unlock()
	require.Empty(t, reports.snapshot())
}
