//go:build !with_clash_dashboard

package clashapi

import (
	E "github.com/sagernet/sing/common/exceptions"

	"github.com/go-chi/chi/v5"
)

func initDashboard() (func(r chi.Router), error) {
	return nil, E.New(`Clash Dashboard is not included in this build, rebuild with -tags with_clash_dashboard`)
}
