//go:build !with_ebpf || (!linux && !android)

package clashapi

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
)

func TestEBPFDiagnosticsRouteIsAbsentWithoutEBPFBuild(t *testing.T) {
	router := chi.NewRouter()
	mountEBPFRouter(router, nil)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/ebpf/", nil))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 without eBPF build support", recorder.Code)
	}
}
