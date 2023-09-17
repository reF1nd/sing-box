//go:build (darwin && cgo) || windows

package tls

import (
	"runtime"
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestCertificatePinSystem(t *testing.T) {
	engine := "apple"
	if runtime.GOOS == "windows" {
		engine = "windows"
	}
	options := option.OutboundTLSOptions{Enabled: true, Engine: engine}
	testCertificatePinOptions(t, options)
	testCertificatePinHandshake(t, options)
}
