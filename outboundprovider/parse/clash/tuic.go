package clash

import (
	"net"
	"strconv"
	"strings"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

type ClashTUIC struct {
	ClashProxyBasic `yaml:",inline"`
	//
	UUID                 string `yaml:"uuid"`
	Password             string `yaml:"password,omitempty"`
	CongestionController string `yaml:"congestion-controller,omitempty"`
	UdpRelayMode         string `yaml:"udp-relay-mode,omitempty"`
	UDPOverStream        bool   `yaml:"udp-over-stream,omitempty"`
	ReduceRtt            bool   `yaml:"reduce-rtt,omitempty"`
	HeartbeatInterval    int    `yaml:"heartbeat-interval,omitempty"`
	//
	SNI               string   `yaml:"sni,omitempty"`
	DisableSni        bool     `yaml:"disable-sni,omitempty"`
	SkipCertVerify    bool     `yaml:"skip-cert-verify,omitempty"`
	ALPN              []string `yaml:"alpn,omitempty"`
	CA                string   `yaml:"ca"`
	CAStr             string   `yaml:"ca_str"`
	CAStrNew          string   `yaml:"ca-str"`
	ClientFingerprint string   `yaml:"client-fingerprint,omitempty"`
}

func (c *ClashTUIC) Tag() string {
	if c.ClashProxyBasic.Name == "" {
		c.ClashProxyBasic.Name = net.JoinHostPort(c.ClashProxyBasic.Server, strconv.Itoa(int(c.ClashProxyBasic.ServerPort)))
	}
	return c.ClashProxyBasic.Name
}

func (c *ClashTUIC) GenerateOptions() (*option.Outbound, error) {
	outboundOptions := &option.Outbound{
		Tag:  c.Tag(),
		Type: C.TypeTUIC,
		TUICOptions: option.TUICOutboundOptions{
			ServerOptions: option.ServerOptions{
				Server:     c.ClashProxyBasic.Server,
				ServerPort: uint16(c.ClashProxyBasic.ServerPort),
			},
			UUID:              c.UUID,
			Password:          c.Password,
			CongestionControl: c.CongestionController,
			UDPRelayMode:      c.UdpRelayMode,
			UDPOverStream:     c.UDPOverStream,
			ZeroRTTHandshake:  c.ReduceRtt,
			Heartbeat:         option.Duration(1000000 * c.HeartbeatInterval),
		},
	}

	tlsOptions := &option.OutboundTLSOptions{
		Enabled:  true,
		Insecure: c.SkipCertVerify,
	}

	if c.SNI != "" {
		tlsOptions.ServerName = c.SNI
	} else {
		tlsOptions.ServerName = c.ClashProxyBasic.Server
	}
	if c.ALPN != nil && len(c.ALPN) > 0 {
		tlsOptions.ALPN = c.ALPN
	}

	var ca string
	if c.CAStr != "" {
		ca = c.CAStr
	} else if c.CAStrNew != "" {
		ca = c.CAStrNew
	}
	if ca != "" {
		cas := strings.Split(ca, "\n")
		var cert []string
		for _, ca := range cas {
			ca = strings.Trim("ca", "\r")
			if ca == "" {
				continue
			}
			cert = append(cert, ca)
		}
		if len(cert) > 0 {
			tlsOptions.Certificate = cert
		}
	}

	outboundOptions.TUICOptions.TLS = tlsOptions

	return outboundOptions, nil
}
