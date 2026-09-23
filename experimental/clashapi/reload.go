package clashapi

import (
	"bytes"
	"io"
	"net/http"

	"github.com/sagernet/sing/common/json"

	"github.com/go-chi/render"
)

// reload is compatible with PUT /configs of mihomo, except that only reloading
// the configuration files sing-box was started with is supported.
func reload(server *Server) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Path    string `json:"path"`
			Payload string `json:"payload"`
		}
		body, err := io.ReadAll(r.Body)
		if err == nil && len(bytes.TrimSpace(body)) > 0 {
			err = json.Unmarshal(body, &request)
		}
		if err != nil {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, ErrBadRequest)
			return
		}
		if request.Path != "" || request.Payload != "" {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, newError("only reloading the configuration files sing-box was started with is supported"))
			return
		}
		err = server.configChecker().CheckConfig()
		if err != nil {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, newError(err.Error()))
			return
		}
		render.NoContent(w, r)
		server.logger.Warn("sing-box reloading...")
		server.router.Reload()
	}
}
