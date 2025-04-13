package clashapi

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"sync/atomic"
	"syscall"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/service"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
)

func restartRouter(ctx context.Context, logFactory log.Factory) http.Handler {
	r := chi.NewRouter()
	r.Post("/", restart(ctx, logFactory))
	return r
}

func restart(ctx context.Context, logFactory log.Factory) http.HandlerFunc {
	return restartHandler(ctx, logFactory.Logger(), os.Executable, restartProcess)
}

func restartHandler(ctx context.Context, logger log.Logger, executable func() (string, error), replaceProcess func(string) error) http.HandlerFunc {
	var restarting atomic.Bool
	return func(w http.ResponseWriter, r *http.Request) {
		instance := service.FromContext[adapter.BoxCloser](ctx)
		if instance == nil {
			render.Status(r, http.StatusServiceUnavailable)
			render.JSON(w, r, newError("instance shutdown is unavailable"))
			return
		}
		execPath, err := executable()
		if err != nil {
			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, newError(err.Error()))
			return
		}
		if !restarting.CompareAndSwap(false, true) {
			render.Status(r, http.StatusConflict)
			render.JSON(w, r, newError("restart already in progress"))
			return
		}
		render.JSON(w, r, render.M{"status": "ok"})
		// Closing the Box also closes this HTTP server. Flush the response first.
		if err := http.NewResponseController(w).Flush(); err != nil {
			restarting.Store(false)
			return
		}
		logger.Info("sing-box restarting")
		go func() {
			// Scope cleanup includes listeners, endpoints, DNS, caches and logging.
			// Report subsequent errors to stderr because the logger is closed too.
			if err := instance.Close(); err != nil {
				fmt.Fprintln(os.Stderr, "sing-box shutdown before restart:", err)
			}
			if err := replaceProcess(execPath); err != nil {
				fmt.Fprintln(os.Stderr, "sing-box restarting:", err)
			}
		}()
	}
}

func restartProcess(execPath string) error {
	if runtime.GOOS == "windows" {
		cmd := exec.Command(execPath, os.Args[1:]...)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Start(); err != nil {
			return err
		}
		os.Exit(0)
	}
	return syscall.Exec(execPath, os.Args, os.Environ())
}
