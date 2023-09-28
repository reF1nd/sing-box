//go:build with_clash_dashboard

package clashapi

import (
	"embed"
	_ "embed"
	"io/fs"
	"net/http"
	"path"

	"github.com/go-chi/chi/v5"
)

//go:embed clash_dashboard
var dashboardFS embed.FS

type fsFunc func(name string) (fs.File, error)

func (f fsFunc) Open(name string) (fs.File, error) {
	return f(name)
}

func initDashboard() (func(r chi.Router), error) {
	handler := fsFunc(func(name string) (fs.File, error) {
		assetPath := path.Join("clash_dashboard", name)
		file, err := dashboardFS.Open(assetPath)
		if err != nil {
			return nil, err
		}
		return file, err
	})

	return func(r chi.Router) {
		r.Get("/ui", http.RedirectHandler("/ui/", http.StatusTemporaryRedirect).ServeHTTP)
		r.Get("/ui/*", http.StripPrefix("/ui", http.FileServer(http.FS(handler))).ServeHTTP)
	}, nil
}
