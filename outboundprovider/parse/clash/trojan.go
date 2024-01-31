package clash

import (
	"errors"
	"net"
	"strconv"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

type ClashTrojan struct {
	ClashProxyBasic `yaml:",inline"`
	//
	Password string `yaml:"password"`
	Flow     string `yaml:"flow"`
	FlowShow string `yaml:"flow-show"`
	UDP      *bool  `yaml:"udp"`
	//
	ALPN              []string `yaml:"alpn"`
	SkipCertVerify    bool     `yaml:"skip-cert-verify"`
	ClientFingerprint string   `yaml:"client-fingerprint"`
	ServerName        string   `yaml:"servername"`
	SNI               string   `yaml:"sni"`
	//
	Network string `yaml:"network"`
	//
	WSOptions   *ClashTransportWebsocket `yaml:"ws-opts"`
	GrpcOptions *ClashTransportGRPC      `yaml:"grpc-opts"`
	//
	RealityOptions *ClashTransportReality `yaml:"reality-opts"`
	//
	TFO bool `yaml:"tfo,omitempty"`
	//
	MuxOptions *ClashSingMuxOptions `yaml:"smux,omitempty"`
}

func (c *ClashTrojan) Tag() string {
	if c.ClashProxyBasic.Name == "" {
		c.ClashProxyBasic.Name = net.JoinHostPort(c.ClashProxyBasic.Server, strconv.Itoa(int(c.ClashProxyBasic.ServerPort)))
	}
	return c.ClashProxyBasic.Name
}

func (c *ClashTrojan) GenerateOptions() (*option.Outbound, error) {
	outboundOptions := &option.Outbound{
		Tag:  c.Tag(),
		Type: C.TypeTrojan,
		TrojanOptions: option.TrojanOutboundOptions{
			ServerOptions: option.ServerOptions{
				Server:     c.ClashProxyBasic.Server,
				ServerPort: uint16(c.ClashProxyBasic.ServerPort),
			},
			Password: c.Password,
		},
	}

	if c.Flow != "" || c.FlowShow != "" {
		return nil, errors.New("trojan flow and flow-show is not supported")
	}

	if c.UDP != nil && !*c.UDP {
		outboundOptions.TrojanOptions.Network = option.NetworkList("tcp")
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

	if c.ClientFingerprint != "" {
		tlsOptions.UTLS = &option.OutboundUTLSOptions{
			Enabled:     true,
			Fingerprint: c.ClientFingerprint,
		}
	}

	if c.ALPN != nil && len(c.ALPN) > 0 {
		tlsOptions.ALPN = c.ALPN
	}

	if c.RealityOptions != nil {
		tlsOptions.Reality = &option.OutboundRealityOptions{
			Enabled:   true,
			PublicKey: c.RealityOptions.PublicKey,
			ShortID:   c.RealityOptions.ShortID,
		}
	}

	outboundOptions.TrojanOptions.TLS = tlsOptions

	switch c.Network {
	case "ws":
		if c.WSOptions == nil {
			c.WSOptions = &ClashTransportWebsocket{}
		}
		websocketOptions := &option.V2RayWebsocketOptions{
			Path:                c.WSOptions.Path,
			MaxEarlyData:        uint32(c.WSOptions.MaxEarlyData),
			EarlyDataHeaderName: c.WSOptions.EarlyDataHeaderName,
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

		websocketOptions.Headers = headers
		outboundOptions.TrojanOptions.Transport = &option.V2RayTransportOptions{
			Type:             C.V2RayTransportTypeWebsocket,
			WebsocketOptions: *websocketOptions,
		}
	case "grpc":
		if c.GrpcOptions == nil {
			c.GrpcOptions = &ClashTransportGRPC{}
		}
		grpcOptions := &option.V2RayGRPCOptions{
			ServiceName: c.GrpcOptions.ServiceName,
		}

		outboundOptions.TrojanOptions.Transport = &option.V2RayTransportOptions{
			Type:        C.V2RayTransportTypeGRPC,
			GRPCOptions: *grpcOptions,
		}
	}

	if c.TFO {
		outboundOptions.TrojanOptions.TCPFastOpen = true
	}

	if c.MuxOptions != nil && c.MuxOptions.Enabled {
		outboundOptions.TrojanOptions.Multiplex = &option.OutboundMultiplexOptions{
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
		outboundOptions.TrojanOptions.DomainStrategy = 0
	case "ipv4":
		outboundOptions.TrojanOptions.DomainStrategy = 3
	case "ipv6":
		outboundOptions.TrojanOptions.DomainStrategy = 4
	case "ipv4-prefer":
		outboundOptions.TrojanOptions.DomainStrategy = 1
	case "ipv6-prefer":
		outboundOptions.TrojanOptions.DomainStrategy = 2
	}

	return outboundOptions, nil
}
