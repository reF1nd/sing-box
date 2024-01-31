package clash

import (
	"net"
	"strconv"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

type ClashHTTP struct {
	ClashProxyBasic `yaml:",inline"`
	//
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	//
	TLS               bool   `yaml:"tls"`
	SkipCertVerify    bool   `yaml:"skip-cert-verify"`
	ServerName        string `yaml:"servername"`
	SNI               string `yaml:"sni"`
	ClientFingerprint string `yaml:"client-fingerprint"`
	//
	TFO bool `yaml:"tfo,omitempty"`
}

func (c *ClashHTTP) Tag() string {
	if c.ClashProxyBasic.Name == "" {
		c.ClashProxyBasic.Name = net.JoinHostPort(c.ClashProxyBasic.Server, strconv.Itoa(int(c.ClashProxyBasic.ServerPort)))
	}
	return c.ClashProxyBasic.Name
}

func (c *ClashHTTP) GenerateOptions() (*option.Outbound, error) {
	outboundOptions := &option.Outbound{
		Tag:  c.Tag(),
		Type: C.TypeHTTP,
		HTTPOptions: option.HTTPOutboundOptions{
			ServerOptions: option.ServerOptions{
				Server:     c.ClashProxyBasic.Server,
				ServerPort: uint16(c.ClashProxyBasic.ServerPort),
			},
			Username: c.Username,
			Password: c.Password,
		},
	}

	if c.TLS {
		tlsOptions := &option.OutboundTLSOptions{
			Enabled:  true,
			Insecure: c.SkipCertVerify,
		}

		if c.ServerName != "" {
			tlsOptions.ServerName = c.ServerName
		} else if c.SNI != "" {
			tlsOptions.ServerName = c.SNI
		} else {
			tlsOptions.ServerName = c.ClashProxyBasic.Server
		}

		if c.ClientFingerprint != "" {
			tlsOptions.UTLS = &option.OutboundUTLSOptions{
				Enabled:     true,
				Fingerprint: c.ClientFingerprint,
			}
		}

		outboundOptions.HTTPOptions.TLS = tlsOptions
	}

	if c.TFO {
		outboundOptions.HTTPOptions.TCPFastOpen = true
	}

	switch c.ClashProxyBasic.IPVersion {
	case "dual":
		outboundOptions.HTTPOptions.DomainStrategy = 0
	case "ipv4":
		outboundOptions.HTTPOptions.DomainStrategy = 3
	case "ipv6":
		outboundOptions.HTTPOptions.DomainStrategy = 4
	case "ipv4-prefer":
		outboundOptions.HTTPOptions.DomainStrategy = 1
	case "ipv6-prefer":
		outboundOptions.HTTPOptions.DomainStrategy = 2
	}

	return outboundOptions, nil
}
