package clash

import (
	"net"
	"strconv"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

type ClashVMess struct {
	ClashProxyBasic `yaml:",inline"`
	//
	UUID                string `yaml:"uuid"`
	AlterID             int    `yaml:"alterId"`
	Cipher              string `yaml:"cipher"`
	UDP                 *bool  `yaml:"udp"`
	PacketEncoding      string `yaml:"packet-encoding"`
	GlobalPadding       bool   `yaml:"global-padding"`
	AuthenticatedLength bool   `yaml:"authenticated-length"`
	//
	TLS               bool   `yaml:"tls"`
	SkipCertVerify    bool   `yaml:"skip-cert-verify"`
	ClientFingerprint string `yaml:"client-fingerprint"`
	ServerName        string `yaml:"servername"`
	SNI               string `yaml:"sni"`
	//
	Network string `yaml:"network"`
	//
	WSOptions    *ClashTransportWebsocket `yaml:"ws-opts"`
	HTTPOptions  *ClashTransportHTTP      `yaml:"http-opts"`
	HTTP2Options *ClashTransportHTTP2     `yaml:"h2-opts"`
	GrpcOptions  *ClashTransportGRPC      `yaml:"grpc-opts"`
	//
	RealityOptions *ClashTransportReality `yaml:"reality-opts"`
	//
	TFO bool `yaml:"tfo,omitempty"`
	//
	MuxOptions *ClashSingMuxOptions `yaml:"smux,omitempty"`
}

func (c *ClashVMess) Tag() string {
	if c.ClashProxyBasic.Name == "" {
		c.ClashProxyBasic.Name = net.JoinHostPort(c.ClashProxyBasic.Server, strconv.Itoa(int(c.ClashProxyBasic.ServerPort)))
	}
	return c.ClashProxyBasic.Name
}

func (c *ClashVMess) GenerateOptions() (*option.Outbound, error) {
	outboundOptions := &option.Outbound{
		Tag:  c.Tag(),
		Type: C.TypeVMess,
		VMessOptions: option.VMessOutboundOptions{
			ServerOptions: option.ServerOptions{
				Server:     c.ClashProxyBasic.Server,
				ServerPort: uint16(c.ClashProxyBasic.ServerPort),
			},
			UUID:                c.UUID,
			AlterId:             c.AlterID,
			Security:            c.Cipher,
			GlobalPadding:       c.GlobalPadding,
			AuthenticatedLength: c.AuthenticatedLength,
			PacketEncoding:      c.PacketEncoding,
		},
	}

	if c.UDP != nil && !*c.UDP {
		outboundOptions.VMessOptions.Network = option.NetworkList("tcp")
	}

	switch c.Network {
	case "ws":
		if c.WSOptions == nil {
			c.WSOptions = &ClashTransportWebsocket{}
		}
		websocketOptions := &option.V2RayWebsocketOptions{
			Path:                c.WSOptions.Path,
			EarlyDataHeaderName: c.WSOptions.EarlyDataHeaderName,
			MaxEarlyData:        uint32(c.WSOptions.MaxEarlyData),
		}

		headers := make(map[string]option.Listable[string])
		if c.WSOptions.Headers != nil {
			for k, v := range c.WSOptions.Headers {
				headers[k] = []string{v}
			}
		}
		if headers["Host"] == nil {
			headers["Host"] = []string{c.ClashProxyBasic.Server}
		}

		if c.TLS {
			tlsOptions := &option.OutboundTLSOptions{
				Enabled:    true,
				ServerName: c.ClashProxyBasic.Server,
				Insecure:   c.SkipCertVerify,
				ALPN:       []string{"http/1.1"},
			}
			if c.ClientFingerprint != "" {
				tlsOptions.UTLS = &option.OutboundUTLSOptions{
					Enabled:     true,
					Fingerprint: c.ClientFingerprint,
				}
			}

			if c.ServerName != "" {
				tlsOptions.ServerName = c.ServerName
			} else if c.SNI != "" {
				tlsOptions.ServerName = c.SNI
			} else if headers["Host"] != nil {
				tlsOptions.ServerName = headers["Host"][0]
			}

			if c.RealityOptions != nil {
				tlsOptions.Reality = &option.OutboundRealityOptions{
					Enabled:   true,
					PublicKey: c.RealityOptions.PublicKey,
					ShortID:   c.RealityOptions.ShortID,
				}
			}

			outboundOptions.VMessOptions.TLS = tlsOptions
		}

		websocketOptions.Headers = headers
		outboundOptions.VMessOptions.Transport = &option.V2RayTransportOptions{
			Type:             C.V2RayTransportTypeWebsocket,
			WebsocketOptions: *websocketOptions,
		}
	case "http":
		if c.HTTPOptions == nil {
			c.HTTPOptions = &ClashTransportHTTP{}
		}
		httpOptions := &option.V2RayHTTPOptions{
			Method: c.HTTPOptions.Method,
		}
		if c.HTTPOptions.Path != nil && len(c.HTTPOptions.Path) > 0 {
			httpOptions.Path = c.HTTPOptions.Path[0]
		}

		headers := make(map[string]option.Listable[string])
		if c.HTTPOptions.Headers != nil {
			for k, v := range c.HTTPOptions.Headers {
				headers[k] = v
			}
		}
		if headers["Host"] != nil {
			httpOptions.Host = headers["Host"]
		}

		if c.TLS {
			tlsOptions := &option.OutboundTLSOptions{
				Enabled:    true,
				ServerName: c.ClashProxyBasic.Server,
				Insecure:   c.SkipCertVerify,
				ALPN:       []string{"h2"},
			}
			if c.ClientFingerprint != "" {
				tlsOptions.UTLS = &option.OutboundUTLSOptions{
					Enabled:     true,
					Fingerprint: c.ClientFingerprint,
				}
			}

			if c.ServerName != "" {
				tlsOptions.ServerName = c.ServerName
			} else if c.SNI != "" {
				tlsOptions.ServerName = c.SNI
			} else if headers["Host"] != nil {
				tlsOptions.ServerName = headers["Host"][0]
			}

			if c.RealityOptions != nil {
				tlsOptions.Reality = &option.OutboundRealityOptions{
					Enabled:   true,
					PublicKey: c.RealityOptions.PublicKey,
					ShortID:   c.RealityOptions.ShortID,
				}
			}

			outboundOptions.VMessOptions.TLS = tlsOptions
		}

		httpOptions.Headers = headers
		outboundOptions.VMessOptions.Transport = &option.V2RayTransportOptions{
			Type:        C.V2RayTransportTypeHTTP,
			HTTPOptions: *httpOptions,
		}
	case "h2":
		if c.HTTP2Options == nil {
			c.HTTP2Options = &ClashTransportHTTP2{}
		}
		http2Options := &option.V2RayHTTPOptions{
			Host: c.HTTP2Options.Host,
			Path: c.HTTP2Options.Path,
		}

		tlsOptions := &option.OutboundTLSOptions{
			Enabled:    true,
			ServerName: c.ClashProxyBasic.Server,
			Insecure:   c.SkipCertVerify,
			ALPN:       []string{"h2"},
		}
		if c.ClientFingerprint != "" {
			tlsOptions.UTLS = &option.OutboundUTLSOptions{
				Enabled:     true,
				Fingerprint: c.ClientFingerprint,
			}
		}

		if c.ServerName != "" {
			tlsOptions.ServerName = c.ServerName
		} else if c.SNI != "" {
			tlsOptions.ServerName = c.SNI
		}

		if c.RealityOptions != nil {
			tlsOptions.Reality = &option.OutboundRealityOptions{
				Enabled:   true,
				PublicKey: c.RealityOptions.PublicKey,
				ShortID:   c.RealityOptions.ShortID,
			}
		}

		outboundOptions.VMessOptions.TLS = tlsOptions
		outboundOptions.VMessOptions.Transport = &option.V2RayTransportOptions{
			Type:        C.V2RayTransportTypeHTTP,
			HTTPOptions: *http2Options,
		}
	case "grpc":
		if c.GrpcOptions == nil {
			c.GrpcOptions = &ClashTransportGRPC{}
		}
		grpcOptions := &option.V2RayGRPCOptions{
			ServiceName: c.GrpcOptions.ServiceName,
		}

		tlsOptions := &option.OutboundTLSOptions{
			Enabled:    true,
			ServerName: c.ClashProxyBasic.Server,
			Insecure:   c.SkipCertVerify,
		}
		if c.ClientFingerprint != "" {
			tlsOptions.UTLS = &option.OutboundUTLSOptions{
				Enabled:     true,
				Fingerprint: c.ClientFingerprint,
			}
		}

		if c.ServerName != "" {
			tlsOptions.ServerName = c.ServerName
		} else if c.SNI != "" {
			tlsOptions.ServerName = c.SNI
		}

		if c.RealityOptions != nil {
			tlsOptions.Reality = &option.OutboundRealityOptions{
				Enabled:   true,
				PublicKey: c.RealityOptions.PublicKey,
				ShortID:   c.RealityOptions.ShortID,
			}
		}

		outboundOptions.VMessOptions.TLS = tlsOptions
		outboundOptions.VMessOptions.Transport = &option.V2RayTransportOptions{
			Type:        C.V2RayTransportTypeGRPC,
			GRPCOptions: *grpcOptions,
		}
	default:
		if c.TLS {
			tlsOptions := &option.OutboundTLSOptions{
				Enabled:    true,
				ServerName: c.ClashProxyBasic.Server,
				Insecure:   c.SkipCertVerify,
			}
			if c.ClientFingerprint != "" {
				tlsOptions.UTLS = &option.OutboundUTLSOptions{
					Enabled:     true,
					Fingerprint: c.ClientFingerprint,
				}
			}

			if c.ServerName != "" {
				tlsOptions.ServerName = c.ServerName
			} else if c.SNI != "" {
				tlsOptions.ServerName = c.SNI
			}

			if c.RealityOptions != nil {
				tlsOptions.Reality = &option.OutboundRealityOptions{
					Enabled:   true,
					PublicKey: c.RealityOptions.PublicKey,
					ShortID:   c.RealityOptions.ShortID,
				}
			}

			outboundOptions.VMessOptions.TLS = tlsOptions
		}
	}

	if c.TFO {
		outboundOptions.VMessOptions.TCPFastOpen = true
	}

	if c.MuxOptions != nil && c.MuxOptions.Enabled {
		outboundOptions.VLESSOptions.Multiplex = &option.OutboundMultiplexOptions{
			Enabled:        true,
			Protocol:       c.MuxOptions.Protocol,
			MaxConnections: c.MuxOptions.MaxConnections,
			MinStreams:     c.MuxOptions.MinStreams,
			MaxStreams:     c.MuxOptions.MaxStreams,
			Padding:        c.MuxOptions.Padding,
		}
	}

	switch c.ClashProxyBasic.IPVersion {
	case "dual":
		outboundOptions.VMessOptions.DomainStrategy = 0
	case "ipv4":
		outboundOptions.VMessOptions.DomainStrategy = 3
	case "ipv6":
		outboundOptions.VMessOptions.DomainStrategy = 4
	case "ipv4-prefer":
		outboundOptions.VMessOptions.DomainStrategy = 1
	case "ipv6-prefer":
		outboundOptions.VMessOptions.DomainStrategy = 2
	}

	return outboundOptions, nil
}
