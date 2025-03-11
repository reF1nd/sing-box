package hysteria2_test

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
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/hysteria2"
	"github.com/sagernet/sing-box/provider/parser"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

const (
	sniExtensionID        uint16 = 0x0000
	chromeTrustAnchorsExt uint16 = 0xca34
)

type testCertBundle struct {
	tlsCert         stdtls.Certificate
	rootPEM         string
	leafPin         string
	intermediatePin string
}

func newHysteria2TestChain(t *testing.T, dnsNames []string, ips []net.IP) testCertBundle {
	t.Helper()
	now := time.Now()
	var (
		parent    *x509.Certificate
		parentKey *ecdsa.PrivateKey
		leafKey   *ecdsa.PrivateKey
		chain     []*x509.Certificate
	)
	names := []string{"hy2-test-root", "hy2-test-intermediate", "hy2-test-leaf"}
	for i, name := range names {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		tmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(int64(i + 1)),
			Subject:               pkix.Name{CommonName: name},
			NotBefore:             now.Add(-time.Hour),
			NotAfter:              now.Add(time.Hour),
			BasicConstraintsValid: true,
			IsCA:                  i < 2,
			KeyUsage:              x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
		if tmpl.IsCA {
			tmpl.KeyUsage |= x509.KeyUsageCertSign
		} else {
			tmpl.DNSNames = dnsNames
			tmpl.IPAddresses = ips
		}
		if parent == nil {
			parent, parentKey = tmpl, key
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
		require.NoError(t, err)
		cert, err := x509.ParseCertificate(der)
		require.NoError(t, err)
		chain = append([]*x509.Certificate{cert}, chain...)
		parent, parentKey, leafKey = cert, key, key
	}

	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: chain[2].Raw})
	leafHash := sha256.Sum256(chain[0].Raw)
	interHash := sha256.Sum256(chain[1].Raw)
	return testCertBundle{
		tlsCert: stdtls.Certificate{
			Certificate: [][]byte{chain[0].Raw, chain[1].Raw, chain[2].Raw},
			PrivateKey:  leafKey,
			Leaf:        chain[0],
		},
		rootPEM:         string(rootPEM),
		leafPin:         hex.EncodeToString(leafHash[:]),
		intermediatePin: hex.EncodeToString(interHash[:]),
	}
}

type observedHello struct {
	serverName string
	extensions []uint16
}

type observedAuth struct {
	host       string
	path       string
	auth       string
	negotiated string
}

type hysteria2TestServer struct {
	port      int
	helloCh   <-chan observedHello
	authCh    <-chan observedAuth
	authCount *atomic.Int32
}

func startHysteria2TestServer(t *testing.T, cert stdtls.Certificate, password string) hysteria2TestServer {
	t.Helper()
	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)

	helloCh := make(chan observedHello, 8)
	authCh := make(chan observedAuth, 8)
	var authCount atomic.Int32

	serverTLS := &stdtls.Config{
		Certificates: []stdtls.Certificate{cert},
		NextProtos:   []string{http3.NextProtoH3},
		GetConfigForClient: func(chi *stdtls.ClientHelloInfo) (*stdtls.Config, error) {
			select {
			case helloCh <- observedHello{
				serverName: chi.ServerName,
				extensions: slices.Clone(chi.Extensions),
			}:
			default:
			}
			return nil, nil
		},
	}
	tr := &quic.Transport{Conn: udpConn}
	tr.SetSingleUse(true)
	ln, err := tr.ListenEarly(serverTLS, &quic.Config{
		EnableDatagrams:      true,
		HandshakeIdleTimeout: 5 * time.Second,
	})
	if err != nil {
		_ = tr.Close()
		_ = udpConn.Close()
		require.NoError(t, err)
	}

	h3Server := &http3.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authCount.Add(1)
			negotiated := ""
			if r.TLS != nil {
				negotiated = r.TLS.NegotiatedProtocol
			}
			select {
			case authCh <- observedAuth{
				host:       r.Host,
				path:       r.URL.Path,
				auth:       r.Header.Get("Hysteria-Auth"),
				negotiated: negotiated,
			}:
			default:
			}
			if r.Method != http.MethodPost || r.URL.Path != "/auth" || r.Header.Get("Hysteria-Auth") != password {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			w.Header().Set("Hysteria-UDP", "true")
			w.Header().Set("Hysteria-CC-RX", "auto")
			w.WriteHeader(233)
		}),
	}
	var wg sync.WaitGroup
	wg.Go(func() {
		_ = h3Server.ServeListener(ln)
	})
	t.Cleanup(func() {
		_ = h3Server.Close()
		_ = ln.Close()
		_ = tr.Close()
		_ = udpConn.Close()
		wg.Wait()
	})
	return hysteria2TestServer{
		port:      udpConn.LocalAddr().(*net.UDPAddr).Port,
		helloCh:   helloCh,
		authCh:    authCh,
		authCount: &authCount,
	}
}

func parseHysteria2LinkOptions(t *testing.T, link string) option.Hysteria2OutboundOptions {
	t.Helper()
	outbound, err := parser.ParseSubscriptionLink(link)
	require.NoError(t, err)
	options, ok := outbound.Options.(*option.Hysteria2OutboundOptions)
	require.True(t, ok)
	return *options
}

func dialHysteria2Handshake(t *testing.T, options option.Hysteria2OutboundOptions) error {
	t.Helper()
	nopLogger := log.NewNOPFactory().Logger()
	outbound, err := hysteria2.NewOutbound(t.Context(), nil, nopLogger, "hy2-test", options)
	require.NoError(t, err)

	scope := adapter.NewScope(t.Context(), nopLogger)
	require.NoError(t, outbound.(*hysteria2.Outbound).Start(adapter.StartStateInitialize, scope))
	defer func() {
		_ = scope.Close()
	}()

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	packetConn, err := outbound.ListenPacket(ctx, M.Socksaddr{})
	if err == nil {
		_ = packetConn.Close()
	}
	return err
}

func readHello(t *testing.T, ch <-chan observedHello) observedHello {
	t.Helper()
	select {
	case hello := <-ch:
		return hello
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for ClientHello")
		return observedHello{}
	}
}

func readAuth(t *testing.T, ch <-chan observedAuth) observedAuth {
	t.Helper()
	select {
	case auth := <-ch:
		return auth
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for HTTP/3 auth request")
		return observedAuth{}
	}
}

func TestHysteria2DisableSNIHandshake(t *testing.T) {
	const password = "secret-password"
	dnsBundle := newHysteria2TestChain(t, []string{"cert.example"}, nil)
	otherBundle := newHysteria2TestChain(t, []string{"cert.example"}, nil)
	ipBundle := newHysteria2TestChain(t, nil, []net.IP{net.IPv4(127, 0, 0, 1)})

	t.Run("DNS positive control sends explicit SNI", func(t *testing.T) {
		srv := startHysteria2TestServer(t, dnsBundle.tlsCert, password)
		opts := parseHysteria2LinkOptions(t, fmt.Sprintf("hy2://%s@127.0.0.1:%d?sni=cert.example", password, srv.port))
		opts.TLS.Certificate = []string{dnsBundle.rootPEM}

		require.NoError(t, dialHysteria2Handshake(t, opts))
		hello := readHello(t, srv.helloCh)
		require.Equal(t, "cert.example", hello.serverName)
		require.Contains(t, hello.extensions, sniExtensionID)
		require.Contains(t, hello.extensions, chromeTrustAnchorsExt)

		auth := readAuth(t, srv.authCh)
		require.Equal(t, "hysteria", auth.host)
		require.Equal(t, http3.NextProtoH3, auth.negotiated)
		require.Equal(t, int32(1), srv.authCount.Load())
	})

	t.Run("DNS with disable_sni=1 omits SNI and verifies certificate", func(t *testing.T) {
		srv := startHysteria2TestServer(t, dnsBundle.tlsCert, password)
		opts := parseHysteria2LinkOptions(t, fmt.Sprintf("hy2://%s@127.0.0.1:%d?sni=cert.example&disable_sni=1", password, srv.port))
		opts.TLS.Certificate = []string{dnsBundle.rootPEM}

		require.NoError(t, dialHysteria2Handshake(t, opts))
		hello := readHello(t, srv.helloCh)
		require.Empty(t, hello.serverName)
		require.NotContains(t, hello.extensions, sniExtensionID)
		require.Contains(t, hello.extensions, chromeTrustAnchorsExt)

		auth := readAuth(t, srv.authCh)
		require.Equal(t, "hysteria", auth.host)
		require.Equal(t, http3.NextProtoH3, auth.negotiated)
		require.Equal(t, int32(1), srv.authCount.Load())
	})

	t.Run("DNS with disable_sni=1 rejects wrong sni", func(t *testing.T) {
		srv := startHysteria2TestServer(t, dnsBundle.tlsCert, password)
		opts := parseHysteria2LinkOptions(t, fmt.Sprintf("hy2://%s@127.0.0.1:%d?sni=wrong.example&disable_sni=1", password, srv.port))
		opts.TLS.Certificate = []string{dnsBundle.rootPEM}

		err := dialHysteria2Handshake(t, opts)
		require.Error(t, err)
		var hostErr x509.HostnameError
		require.ErrorAs(t, err, &hostErr)
		hello := readHello(t, srv.helloCh)
		require.Empty(t, hello.serverName)
		require.NotContains(t, hello.extensions, sniExtensionID)
		require.Zero(t, srv.authCount.Load())
	})

	t.Run("DNS with disable_sni=1 rejects untrusted root", func(t *testing.T) {
		srv := startHysteria2TestServer(t, dnsBundle.tlsCert, password)
		opts := parseHysteria2LinkOptions(t, fmt.Sprintf("hy2://%s@127.0.0.1:%d?sni=cert.example&disable_sni=1", password, srv.port))
		opts.TLS.Certificate = []string{otherBundle.rootPEM}

		err := dialHysteria2Handshake(t, opts)
		require.Error(t, err)
		var authErr x509.UnknownAuthorityError
		require.ErrorAs(t, err, &authErr)
		hello := readHello(t, srv.helloCh)
		require.Empty(t, hello.serverName)
		require.Zero(t, srv.authCount.Load())
	})

	t.Run("CertificateServerName with visible SNI and with disable_sni", func(t *testing.T) {
		srv := startHysteria2TestServer(t, dnsBundle.tlsCert, password)

		visibleOpts := parseHysteria2LinkOptions(t, fmt.Sprintf("hy2://%s@127.0.0.1:%d?sni=wire.example", password, srv.port))
		visibleOpts.TLS.Certificate = []string{dnsBundle.rootPEM}
		visibleOpts.TLS.CertificateServerName = "cert.example"
		require.NoError(t, dialHysteria2Handshake(t, visibleOpts))
		hello := readHello(t, srv.helloCh)
		require.Equal(t, "wire.example", hello.serverName)
		require.Contains(t, hello.extensions, chromeTrustAnchorsExt)
		_ = readAuth(t, srv.authCh)

		wrongVisible := visibleOpts
		tlsCopy := *visibleOpts.TLS
		tlsCopy.CertificateServerName = "wrong.example"
		wrongVisible.TLS = &tlsCopy
		err := dialHysteria2Handshake(t, wrongVisible)
		require.Error(t, err)
		var hostErr x509.HostnameError
		require.ErrorAs(t, err, &hostErr)
		hello = readHello(t, srv.helloCh)
		require.Equal(t, "wire.example", hello.serverName)
		require.Equal(t, int32(1), srv.authCount.Load())

		disabledOpts := parseHysteria2LinkOptions(t, fmt.Sprintf("hy2://%s@127.0.0.1:%d?sni=ignored.example&disable_sni=1", password, srv.port))
		disabledOpts.TLS.Certificate = []string{dnsBundle.rootPEM}
		disabledOpts.TLS.CertificateServerName = "cert.example"
		require.NoError(t, dialHysteria2Handshake(t, disabledOpts))
		hello = readHello(t, srv.helloCh)
		require.Empty(t, hello.serverName)
		require.NotContains(t, hello.extensions, sniExtensionID)
		_ = readAuth(t, srv.authCh)
		require.Equal(t, int32(2), srv.authCount.Load())
	})

	t.Run("IP host without sni verifies IP SAN under disable_sni=1", func(t *testing.T) {
		ipSrv := startHysteria2TestServer(t, ipBundle.tlsCert, password)
		okOpts := parseHysteria2LinkOptions(t, fmt.Sprintf("hy2://%s@127.0.0.1:%d?disable_sni=1", password, ipSrv.port))
		okOpts.TLS.Certificate = []string{ipBundle.rootPEM}
		require.NoError(t, dialHysteria2Handshake(t, okOpts))
		hello := readHello(t, ipSrv.helloCh)
		require.Empty(t, hello.serverName)
		require.NotContains(t, hello.extensions, sniExtensionID)
		_ = readAuth(t, ipSrv.authCh)

		dnsSrv := startHysteria2TestServer(t, dnsBundle.tlsCert, password)
		badOpts := parseHysteria2LinkOptions(t, fmt.Sprintf("hy2://%s@127.0.0.1:%d?disable_sni=1", password, dnsSrv.port))
		badOpts.TLS.Certificate = []string{dnsBundle.rootPEM}
		err := dialHysteria2Handshake(t, badOpts)
		require.Error(t, err)
		var hostErr x509.HostnameError
		require.ErrorAs(t, err, &hostErr)
		hello = readHello(t, dnsSrv.helloCh)
		require.Empty(t, hello.serverName)
		require.Zero(t, dnsSrv.authCount.Load())
	})

	t.Run("leaf pin and issuer pin under disable_sni=1", func(t *testing.T) {
		srv := startHysteria2TestServer(t, dnsBundle.tlsCert, password)

		leafOpts := parseHysteria2LinkOptions(t, fmt.Sprintf("hy2://%s@127.0.0.1:%d?sni=wrong.example&pinSHA256=%s&disable_sni=1", password, srv.port, dnsBundle.leafPin))
		require.NoError(t, dialHysteria2Handshake(t, leafOpts))
		hello := readHello(t, srv.helloCh)
		require.Empty(t, hello.serverName)
		require.NotContains(t, hello.extensions, sniExtensionID)
		require.Contains(t, hello.extensions, chromeTrustAnchorsExt)
		_ = readAuth(t, srv.authCh)

		caOKOpts := parseHysteria2LinkOptions(t, fmt.Sprintf("hy2://%s@127.0.0.1:%d?sni=cert.example&pinSHA256=%s&disable_sni=1", password, srv.port, dnsBundle.intermediatePin))
		require.NoError(t, dialHysteria2Handshake(t, caOKOpts))
		hello = readHello(t, srv.helloCh)
		require.Empty(t, hello.serverName)
		_ = readAuth(t, srv.authCh)

		caBadOpts := parseHysteria2LinkOptions(t, fmt.Sprintf("hy2://%s@127.0.0.1:%d?sni=wrong.example&pinSHA256=%s&disable_sni=1", password, srv.port, dnsBundle.intermediatePin))
		err := dialHysteria2Handshake(t, caBadOpts)
		require.Error(t, err)
		var hostErr x509.HostnameError
		require.ErrorAs(t, err, &hostErr)
		hello = readHello(t, srv.helloCh)
		require.Empty(t, hello.serverName)
		require.Equal(t, int32(2), srv.authCount.Load())
	})

	t.Run("insecure and pin interactions under disable_sni=1", func(t *testing.T) {
		srv := startHysteria2TestServer(t, dnsBundle.tlsCert, password)

		insecureOpts := parseHysteria2LinkOptions(t, fmt.Sprintf("hy2://%s@127.0.0.1:%d?sni=wrong.example&insecure=1&disable_sni=1", password, srv.port))
		require.NoError(t, dialHysteria2Handshake(t, insecureOpts))
		hello := readHello(t, srv.helloCh)
		require.Empty(t, hello.serverName)
		require.NotContains(t, hello.extensions, sniExtensionID)
		require.Contains(t, hello.extensions, chromeTrustAnchorsExt)
		_ = readAuth(t, srv.authCh)

		wrongPin := strings.Repeat("00", 32)
		badPinOpts := parseHysteria2LinkOptions(t, fmt.Sprintf("hy2://%s@127.0.0.1:%d?insecure=1&pinSHA256=%s&disable_sni=1", password, srv.port, wrongPin))
		err := dialHysteria2Handshake(t, badPinOpts)
		require.Error(t, err)
		require.ErrorContains(t, err, "certificate fingerprint mismatch")
		hello = readHello(t, srv.helloCh)
		require.Empty(t, hello.serverName)
		require.Equal(t, int32(1), srv.authCount.Load())

		caBadNameWithInsecure := parseHysteria2LinkOptions(t, fmt.Sprintf("hy2://%s@127.0.0.1:%d?sni=wrong.example&insecure=1&pinSHA256=%s&disable_sni=1", password, srv.port, dnsBundle.intermediatePin))
		err = dialHysteria2Handshake(t, caBadNameWithInsecure)
		require.Error(t, err)
		var hostErr x509.HostnameError
		require.True(t, errors.As(err, &hostErr))
		hello = readHello(t, srv.helloCh)
		require.Empty(t, hello.serverName)
		require.Equal(t, int32(1), srv.authCount.Load())
	})

	t.Run("standard QUIC control with DisableChromeParrot", func(t *testing.T) {
		srv := startHysteria2TestServer(t, dnsBundle.tlsCert, password)
		opts := parseHysteria2LinkOptions(t, fmt.Sprintf("hy2://%s@127.0.0.1:%d?sni=cert.example&disable_sni=1", password, srv.port))
		opts.TLS.Certificate = []string{dnsBundle.rootPEM}
		opts.DisableChromeParrot = true

		require.NoError(t, dialHysteria2Handshake(t, opts))
		hello := readHello(t, srv.helloCh)
		require.Empty(t, hello.serverName)
		require.NotContains(t, hello.extensions, sniExtensionID)
		require.NotContains(t, hello.extensions, chromeTrustAnchorsExt)

		auth := readAuth(t, srv.authCh)
		require.Equal(t, "hysteria", auth.host)
		require.Equal(t, http3.NextProtoH3, auth.negotiated)
	})
}
