package clashapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

type testReloadRouter struct {
	adapter.Router
	reloaded int
}

func (r *testReloadRouter) Reload() {
	r.reloaded++
}

type testConfigChecker struct {
	err     error
	checked int
}

func (c *testConfigChecker) CheckConfig() error {
	c.checked++
	return c.err
}

func TestReloadConfigs(t *testing.T) {
	t.Parallel()

	newTestServer := func(checker adapter.ConfigChecker) (http.Handler, *testReloadRouter) {
		ctx := service.ContextWith[adapter.ConfigChecker](context.Background(), checker)
		router := &testReloadRouter{}
		server := &Server{
			ctx:    ctx,
			router: router,
			logger: log.NewNOPFactory().NewLogger("clash-api"),
		}
		return configRouter(server, log.NewNOPFactory()), router
	}
	put := func(handler http.Handler, body string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPut, "/", strings.NewReader(body))
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}
	errorMessage := func(t *testing.T, response *httptest.ResponseRecorder) string {
		var httpError HTTPError
		require.NoError(t, json.Unmarshal(response.Body.Bytes(), &httpError))
		return httpError.Message
	}

	t.Run("reload not supported", func(t *testing.T) {
		t.Parallel()
		handler, router := newTestServer(nil)
		response := put(handler, "")
		require.Equal(t, http.StatusMethodNotAllowed, response.Code)
		require.Zero(t, router.reloaded)
	})

	for _, body := range []string{"", " ", "{}", `{"path":"","payload":""}`} {
		t.Run("reload with body "+body, func(t *testing.T) {
			t.Parallel()
			checker := &testConfigChecker{}
			handler, router := newTestServer(checker)
			response := put(handler, body)
			require.Equal(t, http.StatusNoContent, response.Code)
			require.Equal(t, 1, checker.checked)
			require.Equal(t, 1, router.reloaded)
		})
	}

	t.Run("invalid body", func(t *testing.T) {
		t.Parallel()
		checker := &testConfigChecker{}
		handler, router := newTestServer(checker)
		response := put(handler, "{")
		require.Equal(t, http.StatusBadRequest, response.Code)
		require.Equal(t, ErrBadRequest.Message, errorMessage(t, response))
		require.Zero(t, checker.checked)
		require.Zero(t, router.reloaded)
	})

	for _, body := range []string{`{"path":"/etc/sing-box/other.json"}`, `{"payload":"{}"}`} {
		t.Run("unsupported "+body, func(t *testing.T) {
			t.Parallel()
			checker := &testConfigChecker{}
			handler, router := newTestServer(checker)
			response := put(handler, body)
			require.Equal(t, http.StatusBadRequest, response.Code)
			require.NotEmpty(t, errorMessage(t, response))
			require.Zero(t, checker.checked)
			require.Zero(t, router.reloaded)
		})
	}

	t.Run("check failed", func(t *testing.T) {
		t.Parallel()
		checker := &testConfigChecker{err: E.New("invalid configuration")}
		handler, router := newTestServer(checker)
		response := put(handler, "")
		require.Equal(t, http.StatusBadRequest, response.Code)
		require.Equal(t, "invalid configuration", errorMessage(t, response))
		require.Equal(t, 1, checker.checked)
		require.Zero(t, router.reloaded)
	})
}
