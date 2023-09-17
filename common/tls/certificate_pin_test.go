package tls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	stdtls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"

	"github.com/stretchr/testify/require"
)

func newCertificatePinChain(t *testing.T) (stdtls.Certificate, []*x509.Certificate) {
	t.Helper()
	now := time.Now()
	var parent *x509.Certificate
	var parentKey *ecdsa.PrivateKey
	var chain []*x509.Certificate
	var leafKey *ecdsa.PrivateKey
	for index, name := range []string{"root", "intermediate", "localhost"} {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		template := &x509.Certificate{
			SerialNumber: big.NewInt(int64(index + 1)), Subject: pkix.Name{CommonName: name},
			DNSNames: []string{name}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
			BasicConstraintsValid: true, IsCA: index < 2, KeyUsage: x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
		if template.IsCA {
			template.KeyUsage |= x509.KeyUsageCertSign
		}
		if parent == nil {
			parent, parentKey = template, key
		}
		der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, parentKey)
		require.NoError(t, err)
		cert, err := x509.ParseCertificate(der)
		require.NoError(t, err)
		chain = append([]*x509.Certificate{cert}, chain...)
		parent, parentKey, leafKey = cert, key, key
	}
	return stdtls.Certificate{Certificate: [][]byte{chain[0].Raw, chain[1].Raw, chain[2].Raw}, PrivateKey: leafKey, Leaf: chain[0]}, chain
}

func certificatePin(cert *x509.Certificate) string {
	hash := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(hash[:])
}

func TestCertificatePinVerification(t *testing.T) {
	_, chain := newCertificatePinChain(t)
	for index, cert := range chain {
		pin := sha256.Sum256(cert.Raw)
		require.NoError(t, VerifyCertificatePinSHA256(pin[:], "localhost", nil, chain))
		wrongName := VerifyCertificatePinSHA256(pin[:], "other", nil, chain)
		expired := VerifyCertificatePinSHA256(pin[:], "localhost", func() time.Time { return time.Now().Add(2 * time.Hour) }, chain)
		missingName := VerifyCertificatePinSHA256(pin[:], "", nil, chain)
		if index == 0 {
			require.NoError(t, wrongName)
			require.NoError(t, expired)
			require.NoError(t, missingName)
		} else {
			require.Error(t, wrongName)
			require.Error(t, expired)
			require.Error(t, missingName)
		}
	}
	_, unrelated := newCertificatePinChain(t)
	pin := sha256.Sum256(unrelated[2].Raw)
	require.Error(t, VerifyCertificatePinSHA256(pin[:], "localhost", nil, append(chain, unrelated[2])))
	require.Error(t, VerifyCertificatePinSHA256(pin[:], "localhost", nil, nil))
	// A CA pin still enforces server-auth usage.
	invalidLeaf := *chain[0]
	invalidLeaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	pin = sha256.Sum256(chain[2].Raw)
	require.Error(t, VerifyCertificatePinSHA256(pin[:], "localhost", nil, []*x509.Certificate{&invalidLeaf, chain[1], chain[2]}))
}

func testCertificatePinOptions(t *testing.T, base option.OutboundTLSOptions) {
	t.Helper()
	for _, tc := range []struct {
		name   string
		modify func(*option.OutboundTLSOptions)
	}{
		{"certificate_sha256", func(o *option.OutboundTLSOptions) { o.CertificateSHA256 = [][]byte{{1}} }},
		{"certificate_public_key_sha256", func(o *option.OutboundTLSOptions) { o.CertificatePublicKeySHA256 = [][]byte{{1}} }},
		{"certificate", func(o *option.OutboundTLSOptions) { o.Certificate = []string{"invalid PEM"} }},
		{"certificate_path", func(o *option.OutboundTLSOptions) { o.CertificatePath = "missing.pem" }},
		{"reality", func(o *option.OutboundTLSOptions) { o.Reality = &option.OutboundRealityOptions{Enabled: true} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			options := base
			options.CertificatePinSHA256 = strings.Repeat("ab", 32)
			tc.modify(&options)
			_, err := NewClient(context.Background(), logger.NOP(), "localhost", options)
			require.ErrorContains(t, err, tc.name)
			if tc.name != "reality" || base.UTLS != nil || base.Engine != "" {
				require.ErrorContains(t, err, "conflict")
			}
			_, err = parseCertificatePinSHA256(options)
			require.ErrorContains(t, err, "conflict")
		})
	}
	for _, value := range []string{" ", "01", strings.Repeat("gg", 32), strings.Repeat("aa", 33)} {
		options := base
		options.CertificatePinSHA256 = value
		_, err := NewClient(context.Background(), logger.NOP(), "localhost", options)
		require.ErrorContains(t, err, "certificate_pin_sha256")
	}
	for _, insecure := range []bool{false, true} {
		options := base
		options.Insecure = insecure
		options.CertificatePinSHA256 = " \n" + strings.Repeat("AB:", 31) + "AB\t"
		_, err := NewClient(context.Background(), logger.NOP(), "localhost", options)
		require.NoError(t, err)
	}
}

func testCertificatePinHandshake(t *testing.T, base option.OutboundTLSOptions) {
	t.Helper()
	certificate, chain := newCertificatePinChain(t)
	for index, cert := range chain {
		for _, insecure := range []bool{false, true} {
			options := base
			options.ServerName = "localhost"
			options.Insecure = insecure
			options.CertificatePinSHA256 = certificatePin(cert)
			config, err := NewClient(context.Background(), logger.NOP(), "", options)
			require.NoError(t, err)
			require.NoError(t, dialCertificatePinConfig(t, certificate, config))
			cloned := config.Clone()
			cloned.SetServerName("other")
			err = dialCertificatePinConfig(t, certificate, cloned)
			if index == 0 {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
			// Changing a clone must not change the original's verifier.
			require.NoError(t, dialCertificatePinConfig(t, certificate, config))
			cloned.SetServerName("localhost")
			require.NoError(t, dialCertificatePinConfig(t, certificate, cloned))
			options.CertificatePinSHA256 = strings.Repeat("00", 32)
			config, err = NewClient(context.Background(), logger.NOP(), "", options)
			require.NoError(t, err)
			require.Error(t, dialCertificatePinConfig(t, certificate, config))
		}
	}
}

func dialCertificatePinConfig(t *testing.T, certificate stdtls.Certificate, config Config) error {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(pinnedCertificateTestTimeout))
		stdtls.Server(conn, &stdtls.Config{Certificates: []stdtls.Certificate{certificate}}).Handshake()
	}()
	ctx, cancel := context.WithTimeout(context.Background(), pinnedCertificateTestTimeout)
	defer cancel()
	conn, err := net.DialTimeout("tcp", listener.Addr().String(), pinnedCertificateTestTimeout)
	require.NoError(t, err)
	defer conn.Close()
	tlsConn, err := ClientHandshake(ctx, conn, config)
	if err == nil {
		tlsConn.Close()
	}
	<-done
	return err
}

func TestCertificatePinSTD(t *testing.T) {
	testCertificatePinOptions(t, option.OutboundTLSOptions{Enabled: true})
	for _, disableSNI := range []bool{false, true} {
		testCertificatePinHandshake(t, option.OutboundTLSOptions{Enabled: true, DisableSNI: disableSNI})
	}
}
