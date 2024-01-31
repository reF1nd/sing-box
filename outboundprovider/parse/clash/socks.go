package clash

import (
	"errors"
	"net"
	"strconv"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

type ClashSocks struct {
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
	UDP *bool `yaml:"udp"`
	//
	TFO bool `yaml:"tfo,omitempty"`
}

func (c *ClashSocks) Tag() string {
	if c.ClashProxyBasic.Name == "" {
		c.ClashProxyBasic.Name = net.JoinHostPort(c.ClashProxyBasic.Server, strconv.Itoa(int(c.ClashProxyBasic.ServerPort)))
	}
	return c.ClashProxyBasic.Name
}

func (c *ClashSocks) GenerateOptions() (*option.Outbound, error) {
	outboundOptions := &option.Outbound{
		Tag:  c.Tag(),
		Type: C.TypeSOCKS,
		SocksOptions: option.SocksOutboundOptions{
			ServerOptions: option.ServerOptions{
				Server:     c.ClashProxyBasic.Server,
				ServerPort: uint16(c.ClashProxyBasic.ServerPort),
			},
			Username: c.Username,
			Password: c.Password,
			Version:  "5",
		},
	}

	if c.TLS {
		return nil, errors.New("socks5 tls is not supported")
	}
	if c.UDP != nil && !*c.UDP {
		outboundOptions.SocksOptions.Network = option.NetworkList("tcp")
	}

	if c.TFO {
		outboundOptions.SocksOptions.TCPFastOpen = true
	}

	switch c.ClashProxyBasic.IPVersion {
	case "dual":
		outboundOptions.SocksOptions.DomainStrategy = 0
	case "ipv4":
		outboundOptions.SocksOptions.DomainStrategy = 3
	case "ipv6":
		outboundOptions.SocksOptions.DomainStrategy = 4
	case "ipv4-prefer":
		outboundOptions.SocksOptions.DomainStrategy = 1
	case "ipv6-prefer":
		outboundOptions.SocksOptions.DomainStrategy = 2
	}

	return outboundOptions, nil
}
