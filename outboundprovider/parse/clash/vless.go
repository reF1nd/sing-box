package clash

import (
	"errors"
	"net"
	"strconv"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

type ClashVLESS struct {
	ClashProxyBasic `yaml:",inline"`
	//
	UUID           string  `yaml:"uuid"`
	Flow           string  `yaml:"flow"`
	FlowShow       string  `yaml:"flow-show"`
	XUDP           bool    `yaml:"xudp,omitempty"`
	PacketAddr     bool    `yaml:"packet-addr,omitempty"`
	UDP            *bool   `yaml:"udp"`
	PacketEncoding *string `yaml:"packet-encoding"`
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

func (c *ClashVLESS) Tag() string {
	if c.ClashProxyBasic.Name == "" {
		c.ClashProxyBasic.Name = net.JoinHostPort(c.ClashProxyBasic.Server, strconv.Itoa(int(c.ClashProxyBasic.ServerPort)))
	}
	return c.ClashProxyBasic.Name
}

func (c *ClashVLESS) GenerateOptions() (*option.Outbound, error) {
	outboundOptions := &option.Outbound{
		Tag:  c.Tag(),
		Type: C.TypeVLESS,
		VLESSOptions: option.VLESSOutboundOptions{
			ServerOptions: option.ServerOptions{
				Server:     c.ClashProxyBasic.Server,
				ServerPort: uint16(c.ClashProxyBasic.ServerPort),
			},
			UUID: c.UUID,
			Flow: c.Flow,
		},
	}

	if c.FlowShow != "" {
		return nil, errors.New("flow-show is not supported")
	}

	if c.UDP != nil && !*c.UDP {
		outboundOptions.VLESSOptions.Network = option.NetworkList("tcp")
	}

	if c.PacketEncoding != nil {
		outboundOptions.VLESSOptions.PacketEncoding = new(string)
		*outboundOptions.VLESSOptions.PacketEncoding = *c.PacketEncoding
	} else if c.XUDP {
		outboundOptions.VLESSOptions.PacketEncoding = new(string)
		*outboundOptions.VLESSOptions.PacketEncoding = "xudp"
	} else if c.PacketAddr {
		outboundOptions.VLESSOptions.PacketEncoding = new(string)
		*outboundOptions.VLESSOptions.PacketEncoding = "packetaddr"
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

			outboundOptions.VLESSOptions.TLS = tlsOptions
		}

		websocketOptions.Headers = headers
		outboundOptions.VLESSOptions.Transport = &option.V2RayTransportOptions{
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

			outboundOptions.VLESSOptions.TLS = tlsOptions
		}

		httpOptions.Headers = headers
		outboundOptions.VLESSOptions.Transport = &option.V2RayTransportOptions{
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

		outboundOptions.VLESSOptions.TLS = tlsOptions
		outboundOptions.VLESSOptions.Transport = &option.V2RayTransportOptions{
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

		outboundOptions.VLESSOptions.TLS = tlsOptions
		outboundOptions.VLESSOptions.Transport = &option.V2RayTransportOptions{
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

			outboundOptions.VLESSOptions.TLS = tlsOptions
		}
	}

	if c.TFO {
		outboundOptions.VLESSOptions.TCPFastOpen = true
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
		outboundOptions.VLESSOptions.DomainStrategy = 0
	case "ipv4":
		outboundOptions.VLESSOptions.DomainStrategy = 3
	case "ipv6":
		outboundOptions.VLESSOptions.DomainStrategy = 4
	case "ipv4-prefer":
		outboundOptions.VLESSOptions.DomainStrategy = 1
	case "ipv6-prefer":
		outboundOptions.VLESSOptions.DomainStrategy = 2
	}

	return outboundOptions, nil
}
