package clash

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

type ClashHysteria struct {
	ClashProxyBasic `yaml:",inline"`
	//
	Ports               string `yaml:"ports"`
	AuthStr             string `yaml:"auth_str"`
	AuthStrNew          string `yaml:"auth-str"`
	Obfs                string `yaml:"obfs"`
	Protocol            string `yaml:"protocol"`
	Up                  string `yaml:"up"`
	Down                string `yaml:"down"`
	RecvWindowConn      uint64 `yaml:"recv_window_conn"`
	RecvWindowConnNew   uint64 `yaml:"recv-window-conn"`
	RecvWindow          uint64 `yaml:"recv_window"`
	RecvWindowNew       uint64 `yaml:"recv-window"`
	DisableMTUDiscovery bool   `yaml:"disable_mtu_discovery"`
	FastOpen            bool   `yaml:"fast-open"`
	//
	ALPN              []string `yaml:"alpn"`
	ServerName        string   `yaml:"servername"`
	SNI               string   `yaml:"sni"`
	SkipCertVerify    bool     `yaml:"skip-cert-verify"`
	ClientFingerprint string   `yaml:"client-fingerprint"`
	CA                string   `yaml:"ca"`
	CAStr             string   `yaml:"ca_str"`
	CAStrNew          string   `yaml:"ca-str"`
}

func (c *ClashHysteria) Tag() string {
	if c.ClashProxyBasic.Name == "" {
		c.ClashProxyBasic.Name = net.JoinHostPort(c.ClashProxyBasic.Server, strconv.Itoa(int(c.ClashProxyBasic.ServerPort)))
	}
	return c.ClashProxyBasic.Name
}

func (c *ClashHysteria) GenerateOptions() (*option.Outbound, error) {
	outboundOptions := &option.Outbound{
		Tag:  c.Tag(),
		Type: C.TypeHysteria,
		HysteriaOptions: option.HysteriaOutboundOptions{
			ServerOptions: option.ServerOptions{
				Server:     c.ClashProxyBasic.Server,
				ServerPort: uint16(c.ClashProxyBasic.ServerPort),
			},
		},
	}

	if c.Ports != "" {
		return nil, fmt.Errorf("ports is not supported")
	}

	if c.AuthStr != "" {
		outboundOptions.HysteriaOptions.AuthString = c.AuthStr
	} else if c.AuthStrNew != "" {
		outboundOptions.HysteriaOptions.AuthString = c.AuthStrNew
	}

	outboundOptions.HysteriaOptions.Obfs = c.Obfs
	if c.Protocol != "udp" {
		return nil, fmt.Errorf("wechat-video and faketcp are not supported")
	}

	upUint64, err := strconv.ParseUint(c.Up, 10, 64)
	if err == nil {
		outboundOptions.HysteriaOptions.UpMbps = int(upUint64)
	} else {
		outboundOptions.HysteriaOptions.Up = c.Up
	}

	downUint64, err := strconv.ParseUint(c.Down, 10, 64)
	if err == nil {
		outboundOptions.HysteriaOptions.DownMbps = int(downUint64)
	} else {
		outboundOptions.HysteriaOptions.Down = c.Down
	}

	if c.RecvWindowConn > 0 {
		outboundOptions.HysteriaOptions.ReceiveWindowConn = c.RecvWindowConn
	} else if c.RecvWindowConnNew > 0 {
		outboundOptions.HysteriaOptions.ReceiveWindowConn = c.RecvWindowConnNew
	}

	if c.RecvWindow > 0 {
		outboundOptions.HysteriaOptions.ReceiveWindow = c.RecvWindow
	} else if c.RecvWindowNew > 0 {
		outboundOptions.HysteriaOptions.ReceiveWindow = c.RecvWindowNew
	}

	outboundOptions.HysteriaOptions.DisableMTUDiscovery = c.DisableMTUDiscovery

	if c.FastOpen {
		return nil, fmt.Errorf("fast-open is not supported")
	}

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

	outboundOptions.HysteriaOptions.TLS = tlsOptions

	return outboundOptions, nil
}
