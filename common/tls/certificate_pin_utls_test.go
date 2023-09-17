//go:build with_utls

package tls

import (
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestCertificatePinUTLS(t *testing.T) {
	options := option.OutboundTLSOptions{Enabled: true, UTLS: &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "chrome"}}
	testCertificatePinOptions(t, options)
	for _, disableSNI := range []bool{false, true} {
		options.DisableSNI = disableSNI
		testCertificatePinHandshake(t, options)
	}
}
