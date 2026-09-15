//go:build with_ebpf && (linux || android)

package clashapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"

	"github.com/go-chi/chi/v5"
)

// fakeEBPFInbound is the minimal adapter.Inbound plus ebpfDiagnosticsProvider
// double this file's tests need: nothing about Start/Close/Type is
// exercised by the route, so they are no-ops.
type fakeEBPFInbound struct {
	tag         string
	diagnostics any
}

func (f *fakeEBPFInbound) Start(adapter.StartStage) error { return nil }
func (f *fakeEBPFInbound) Close() error                   { return nil }
func (f *fakeEBPFInbound) Type() string                   { return "ebpf" }
func (f *fakeEBPFInbound) Tag() string                    { return f.tag }
func (f *fakeEBPFInbound) DiagnosticsJSON() any           { return f.diagnostics }

// plainInbound implements adapter.Inbound without ebpfDiagnosticsProvider,
// standing in for every non-eBPF inbound type the manager also holds.
type plainInbound struct{ tag string }

func (p *plainInbound) Start(adapter.StartStage) error { return nil }
func (p *plainInbound) Close() error                   { return nil }
func (p *plainInbound) Type() string                   { return "direct" }
func (p *plainInbound) Tag() string                    { return p.tag }

type fakeInboundManager struct {
	inbounds []adapter.Inbound
}

func (m *fakeInboundManager) Start(adapter.StartStage) error { return nil }
func (m *fakeInboundManager) Close() error                   { return nil }
func (m *fakeInboundManager) Inbounds() []adapter.Inbound    { return m.inbounds }
func (m *fakeInboundManager) Get(tag string) (adapter.Inbound, bool) {
	for _, inbound := range m.inbounds {
		if inbound.Tag() == tag {
			return inbound, true
		}
	}
	return nil, false
}

func (m *fakeInboundManager) Remove(tag string) error { return nil }
func (m *fakeInboundManager) Create(
	ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, inboundType string, options any,
) error {
	return nil
}

// TestGetEBPFDiagnosticsReportsOnlyEBPFInbounds proves the route filters by
// the duck-typed interface rather than assuming every inbound is eBPF, and
// that it surfaces exactly the value DiagnosticsJSON returned.
func TestGetEBPFDiagnosticsReportsOnlyEBPFInbounds(t *testing.T) {
	manager := &fakeInboundManager{inbounds: []adapter.Inbound{
		&plainInbound{tag: "direct-in"},
		&fakeEBPFInbound{tag: "ebpf-in", diagnostics: map[string]any{"tag": "ebpf-in", "state": "normal"}},
	}}
	router := chi.NewRouter()
	mountEBPFRouter(router, manager)

	request := httptest.NewRequest(http.MethodGet, "/ebpf/", nil)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", recorder.Code, recorder.Body.String())
	}
	var decoded struct {
		EBPF []map[string]any `json:"ebpf"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &decoded); err != nil {
		t.Fatalf("decode response: %v (body: %s)", err, recorder.Body.String())
	}
	if len(decoded.EBPF) != 1 {
		t.Fatalf("ebpf entries = %d, want exactly 1 (the plain inbound must not appear)", len(decoded.EBPF))
	}
	if decoded.EBPF[0]["tag"] != "ebpf-in" {
		t.Fatalf("ebpf[0] = %v, want tag=ebpf-in", decoded.EBPF[0])
	}
}

func TestEBPFDiagnosticsRouteRequiresAnEBPFInbound(t *testing.T) {
	for _, manager := range []adapter.InboundManager{
		nil,
		&fakeInboundManager{inbounds: []adapter.Inbound{&plainInbound{tag: "direct-in"}}},
	} {
		router := chi.NewRouter()
		mountEBPFRouter(router, manager)
		request := httptest.NewRequest(http.MethodGet, "/ebpf/", nil)
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404 without an eBPF inbound", recorder.Code)
		}
	}
}
