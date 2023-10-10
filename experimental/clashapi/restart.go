//go:build !windows && !android && !ios

package clashapi

import (
	"net/http"
	"os"
	"syscall"

	"github.com/go-chi/render"
)

func restart(server *Server) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			server.logger.Warn("box restarting...")
			pid := os.Getpid()
			err := syscall.Kill(pid, syscall.SIGHUP)
			if err != nil {
				server.logger.Error("failed to restart: ", err)
			}
		}()
		render.NoContent(w, r)
	}
}
