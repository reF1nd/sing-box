//go:build !ios

package clashapi

import (
	"net/http"

	"github.com/go-chi/render"
)

func reload(server *Server) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		render.NoContent(w, r)
		if err := http.NewResponseController(w).Flush(); err != nil {
			return
		}
		server.logger.Warn("sing-box reloading configuration...")
		server.router.Reload()
	}
}
