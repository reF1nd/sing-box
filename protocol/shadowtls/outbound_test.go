package shadowtls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	stdTLS "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-shadowtls"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

type testShadowTLSHandler struct{}

func (testShadowTLSHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	defer conn.Close()
	if onClose != nil {
		defer onClose(nil)
	}
	_, _ = conn.Write([]byte("ok"))
}

func startShadowTLSv3TestServer(t *testing.T, dnsName string) (uint16, *x509.Certificate, string) {
	t.Helper()
	now := time.Now()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: dnsName},
		DNSNames:              []string{dnsName},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	tlsCert := stdTLS.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: cert}

	tlsListener, err := stdTLS.Listen("tcp", "127.0.0.1:0", &stdTLS.Config{
		Certificates: []stdTLS.Certificate{tlsCert},
		MinVersion:   stdTLS.VersionTLS13,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = tlsListener.Close() })
	go func() {
		for {
			conn, acceptErr := tlsListener.Accept()
			if acceptErr != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 64)
				_, _ = c.Read(buf)
			}(conn)
		}
	}()

	service, err := shadowtls.NewService(shadowtls.ServiceConfig{
		Version: 3,
		Users:   []shadowtls.User{{Name: "test", Password: "secret"}},
		Handshake: shadowtls.HandshakeConfig{
			Server: M.ParseSocksaddr(tlsListener.Addr().String()),
			Dialer: N.SystemDialer,
		},
		Handler: testShadowTLSHandler{},
		Logger:  logger.NOP(),
	})
	require.NoError(t, err)

	stlsListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = stlsListener.Close() })
	go func() {
		for {
			conn, acceptErr := stlsListener.Accept()
			if acceptErr != nil {
				return
			}
			go func(c net.Conn) {
				_ = service.NewConnection(context.Background(), c, M.SocksaddrFromNet(c.RemoteAddr()), M.Socksaddr{}, nil)
			}(conn)
		}
	}()

	return uint16(stlsListener.Addr().(*net.TCPAddr).Port), cert, certPEM
}

func TestShadowTLSv3DefaultTLSCertificatePin(t *testing.T) {
	port, cert, _ := startShadowTLSv3TestServer(t, "pin.example.test")
	sum := sha256.Sum256(cert.Raw)
	goodPin := hex.EncodeToString(sum[:])
	wrongPin := strings.Repeat("00", sha256.Size)
	if wrongPin == goodPin {
		wrongPin = strings.Repeat("ff", sha256.Size)
	}

	newClient := func(pin string) *Outbound {
		out, err := NewOutbound(context.Background(), nil, log.NewNOPFactory().NewLogger("shadowtls"), "stls", option.ShadowTLSOutboundOptions{
			ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: port},
			Version:       3,
			Password:      "secret",
			OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
				TLS: &option.OutboundTLSOptions{
					Enabled:              true,
					ServerName:           "pin.example.test",
					CertificatePinSHA256: pin,
				},
			},
		})
		require.NoError(t, err)
		return out.(*Outbound)
	}

	conn, err := newClient(goodPin).DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr("example.com:80"))
	require.NoError(t, err)
	_ = conn.Close()

	_, err = newClient(wrongPin).DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr("example.com:80"))
	require.Error(t, err)
	require.ErrorContains(t, err, "certificate fingerprint mismatch")
}

func TestShadowTLSv3DefaultTLSCertificateServerName(t *testing.T) {
	port, _, certPEM := startShadowTLSv3TestServer(t, "san.example.test")

	newClient := func(certServerName string) *Outbound {
		out, err := NewOutbound(context.Background(), nil, log.NewNOPFactory().NewLogger("shadowtls"), "stls", option.ShadowTLSOutboundOptions{
			ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: port},
			Version:       3,
			Password:      "secret",
			OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
				TLS: &option.OutboundTLSOptions{
					Enabled:               true,
					ServerName:            "sni.example.test",
					CertificateServerName: certServerName,
					Certificate:           []string{certPEM},
				},
			},
		})
		require.NoError(t, err)
		return out.(*Outbound)
	}

	conn, err := newClient("san.example.test").DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr("example.com:80"))
	require.NoError(t, err)
	_ = conn.Close()

	_, err = newClient("wrong.example.test").DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr("example.com:80"))
	require.Error(t, err)
	require.ErrorContains(t, err, "wrong.example.test")
}
