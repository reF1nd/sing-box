package tls

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"strings"
	"time"

	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

func parseCertificatePinSHA256(options option.OutboundTLSOptions) ([]byte, error) {
	if options.CertificatePinSHA256 == "" {
		return nil, nil
	}
	if len(options.CertificateSHA256) > 0 || len(options.CertificatePublicKeySHA256) > 0 || len(options.Certificate) > 0 || options.CertificatePath != "" {
		return nil, E.New("certificate_pin_sha256 is conflict with certificate_sha256, certificate_public_key_sha256, certificate or certificate_path")
	}
	if options.Reality != nil && options.Reality.Enabled {
		return nil, E.New("certificate_pin_sha256 is conflict with reality")
	}
	fingerprint := strings.TrimSpace(strings.ReplaceAll(options.CertificatePinSHA256, ":", ""))
	pin, err := hex.DecodeString(fingerprint)
	if err != nil {
		return nil, E.Cause(err, "decode certificate_pin_sha256")
	}
	if len(pin) != sha256.Size {
		return nil, E.New("certificate_pin_sha256 must be a SHA-256 fingerprint (32 bytes)")
	}
	return pin, nil
}

// VerifyCertificatePinSHA256 accepts an exact leaf pin or verifies the leaf against a pinned issuer.
func VerifyCertificatePinSHA256(pin []byte, serverName string, timeFunc func() time.Time, certificates []*x509.Certificate) error {
	for index, certificate := range certificates {
		hash := sha256.Sum256(certificate.Raw)
		if !bytes.Equal(pin, hash[:]) {
			continue
		}
		// An exact leaf pin is sufficient. A pinned issuer must also validate
		// the leaf's chain, hostname, validity period and server-auth usage.
		if index == 0 {
			return nil
		}
		if serverName == "" {
			return errMissingServerName
		}
		options := x509.VerifyOptions{
			Roots:         x509.NewCertPool(),
			Intermediates: x509.NewCertPool(),
			DNSName:       serverName,
		}
		if timeFunc != nil {
			options.CurrentTime = timeFunc()
		}
		options.Roots.AddCert(certificate)
		for _, intermediate := range certificates[1 : index+1] {
			options.Intermediates.AddCert(intermediate)
		}
		_, err := certificates[0].Verify(options)
		return err
	}
	return E.New("certificate fingerprint mismatch")
}
