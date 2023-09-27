//go:build with_embedded_tor && ios

package outbound

import (
	"github.com/cretz/bine/tor"
	"github.com/ooni/go-libtor"
)

func newConfig() tor.StartConf {
	return tor.StartConf{
		ProcessCreator:         libtor.Creator,
		UseEmbeddedControlConn: true,
	}
}
