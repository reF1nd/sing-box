//go:build with_ebpf && (linux || android)

package clashapi

import (
	"net/http"

	"github.com/sagernet/sing-box/adapter"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
)

// ebpfDiagnosticsProvider is the eBPF inbound's runtime status method,
// declared here rather than imported from protocol/ebpf so this package
// never needs the with_ebpf build tag: any inbound that happens to
// implement it is reported, and inbounds that don't simply never match.
//
// The eBPF inbound (protocol/ebpf.Inbound) is the only current
// implementation. A standalone `sing-box tools ebpf status` process cannot
// see this data at all, since it never had a running instance to read it
// from; this endpoint exists because the Clash API server already runs
// inside that instance and already has an authenticated, external-facing
// HTTP surface, which reading a running instance's status otherwise has no
// route to.
type ebpfDiagnosticsProvider interface {
	// DiagnosticsJSON returns a JSON-marshalable value; the concrete type is
	// protocol/ebpf.EBPFDiagnostics, kept as `any` here so this package does
	// not need to import protocol/ebpf (and so does not need its build tag).
	DiagnosticsJSON() any
}

func ebpfRouter(manager adapter.InboundManager) http.Handler {
	r := chi.NewRouter()
	r.Get("/", getEBPFDiagnostics(manager))
	return r
}

func mountEBPFRouter(router chi.Router, manager adapter.InboundManager) {
	if manager == nil {
		return
	}
	for _, inbound := range manager.Inbounds() {
		if _, loaded := inbound.(ebpfDiagnosticsProvider); loaded {
			router.Mount("/ebpf", ebpfRouter(manager))
			return
		}
	}
}

func getEBPFDiagnostics(manager adapter.InboundManager) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if manager == nil {
			render.Status(r, http.StatusNotFound)
			render.JSON(w, r, newError("inbound manager unavailable"))
			return
		}
		diagnostics := make([]any, 0)
		for _, inbound := range manager.Inbounds() {
			provider, ok := inbound.(ebpfDiagnosticsProvider)
			if !ok {
				continue
			}
			diagnostics = append(diagnostics, provider.DiagnosticsJSON())
		}
		render.JSON(w, r, render.M{
			"ebpf": diagnostics,
		})
	}
}
