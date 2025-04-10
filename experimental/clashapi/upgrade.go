package clashapi

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
)

func upgradeRouter(server *Server) http.Handler {
	r := chi.NewRouter()
	r.Post("/ui", updateUI(server))
	return r
}

func updateUI(server *Server) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		err := server.checkAndDownloadExternalUI(true)
		if err != nil {
			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, newError(err.Error()))
			return
		}
		render.NoContent(w, r)
	}
}
