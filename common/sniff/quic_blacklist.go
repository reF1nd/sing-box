package sniff

import (
	"slices"

	"github.com/sagernet/sing-box/common/ja3"
)

const (
	// X25519Kyber768Draft00 - post-quantum curve used by Go crypto/tls
	x25519Kyber768Draft00 uint16 = 0x11EC // 4588
	// renegotiation_info extension used by Go crypto/tls
	extensionRenegotiationInfo uint16 = 0xFF01 // 65281
)

// isQUICGo detects native quic-go by checking for Go crypto/tls specific features.
// Note: uQUIC with Chromium mimicry cannot be reliably distinguished from real Chromium
// since it uses the same TLS fingerprint, so it will be identified as Chromium.
func isQUICGo(fingerprint *ja3.ClientHello) bool {
	if slices.Contains(fingerprint.EllipticCurves, x25519Kyber768Draft00) {
		return true
	}
	return slices.Contains(fingerprint.Extensions, extensionRenegotiationInfo)
}
