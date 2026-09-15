//go:build !with_ebpf || (!linux && !android)

package clashapi

import (
	"github.com/sagernet/sing-box/adapter"

	"github.com/go-chi/chi/v5"
)

func mountEBPFRouter(chi.Router, adapter.InboundManager) {}
