package parser

import (
	"context"
	"encoding/base64"
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/byteformats"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/json/badoption"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"

	"github.com/metacubex/mihomo/common/structure"
	"gopkg.in/yaml.v3"
)

type ClashConfig struct {
	Proxies []map[string]any `yaml:"proxies"`
}

func ParseClashSubscription(ctx context.Context, content string) ([]option.Outbound, error) {
	config := &ClashConfig{}
	err := yaml.Unmarshal([]byte(content), &config)
	if err != nil {
		return nil, E.Cause(err, "parse clash config")
	}
	decoder := structure.NewDecoder(structure.Option{TagName: "proxy", WeaklyTypedInput: true})
	var outbounds []option.Outbound
	for i, proxyMapping := range config.Proxies {
		basicOption := &BasicOption{}
		err = decoder.Decode(proxyMapping, basicOption)
		if err != nil {
			return nil, E.Cause(err, "decode option", i)
		}
		outbound := option.Outbound{
			Tag: basicOption.Name,
		}
		switch basicOption.Type {
		case "ss":
			ssOption := &ShadowSocksOption{}
			err = decoder.Decode(proxyMapping, ssOption)
			if err != nil {
				return nil, E.Cause(err, "decode vmess option", i)
			}
			outbound.Type = C.TypeShadowsocks
			options := &option.ShadowsocksOutboundOptions{
				Password:      ssOption.Password,
				Method:        clashShadowsocksCipher(ssOption.Cipher),
				Plugin:        clashPluginName(ssOption.Plugin),
				PluginOptions: clashPluginOptions(ssOption.Plugin, ssOption.PluginOpts),
				Network:       clashNetworks(ssOption.UDP),
				UDPOverTCP: &option.UDPOverTCPOptions{
					Enabled: ssOption.UDPOverTCP,
					Version: uint8(ssOption.UDPOverTCPVersion),
				},
				Multiplex: basicOption.SMUX.Build(),
			}
			options.DialerOptions, options.ServerOptions = clashBasicOption(ctx, basicOption)
			outbound.Options = options
		case "tuic":
			tuicOption := &TuicOption{}
			err = decoder.Decode(proxyMapping, tuicOption)
			if err != nil {
				return nil, E.Cause(err, "decode tuic option", i)
			}
			outbound.Type = C.TypeTUIC
			options := &option.TUICOutboundOptions{
				UUID:              tuicOption.UUID,
				Password:          tuicOption.Password,
				CongestionControl: tuicOption.CongestionController,
				UDPRelayMode:      tuicOption.UdpRelayMode,
				UDPOverStream:     tuicOption.UDPOverStream,
				ZeroRTTHandshake:  tuicOption.ReduceRtt,
				Heartbeat:         badoption.Duration(tuicOption.HeartbeatInterval),
			}
			options.TLS = &option.OutboundTLSOptions{
				Enabled:         true,
				DisableSNI:      tuicOption.DisableSni,
				ServerName:      tuicOption.SNI,
				Insecure:        tuicOption.SkipCertVerify,
				ALPN:            tuicOption.ALPN,
				Certificate:     strings.Split(tuicOption.CustomCAString, "\n"),
				CertificatePath: tuicOption.CustomCA,
				ECH:             clashECHOptions(tuicOption.ECHOpts),
			}
			basicOption.TFO = tuicOption.FastOpen
			options.DialerOptions, options.ServerOptions = clashBasicOption(ctx, basicOption)
			outbound.Options = options
		case "vmess":
			vmessOption := &VmessOption{}
			err = decoder.Decode(proxyMapping, vmessOption)
			if err != nil {
				return nil, E.Cause(err, "decode vmess option", i)
			}
			outbound.Type = C.TypeVMess
			options := &option.VMessOutboundOptions{
				UUID:                vmessOption.UUID,
				Security:            vmessOption.Cipher,
				AlterId:             vmessOption.AlterID,
				GlobalPadding:       vmessOption.GlobalPadding,
				AuthenticatedLength: vmessOption.AuthenticatedLength,
				Network:             clashNetworks(vmessOption.UDP),
				PacketEncoding:      vmessOption.PacketEncoding,
				Multiplex:           basicOption.SMUX.Build(),
				Transport:           clashTransport(vmessOption.Network, vmessOption.HTTPOpts, vmessOption.HTTP2Opts, vmessOption.GrpcOpts, vmessOption.WSOpts),
			}
			options.TLS = clashTLSOptions(&option.OutboundTLSOptions{
				Enabled:    vmessOption.TLS,
				ServerName: vmessOption.ServerName,
				Insecure:   vmessOption.SkipCertVerify,
				ALPN:       vmessOption.ALPN,
				UTLS:       clashClientFingerprint(vmessOption.ClientFingerprint),
				ECH:        clashECHOptions(vmessOption.ECHOpts),
				Reality:    vmessOption.RealityOpts.Build(),
			})
			options.DialerOptions, options.ServerOptions = clashBasicOption(ctx, basicOption)
			outbound.Options = options
		case "vless":
			vlessOption := &VlessOption{}
			err = decoder.Decode(proxyMapping, vlessOption)
			if err != nil {
				return nil, E.Cause(err, "decode vless option", i)
			}
			outbound.Type = C.TypeVLESS
			if vlessOption.XUDP {
				vlessOption.PacketEncoding = "xudp"
			}
			options := &option.VLESSOutboundOptions{
				UUID:           vlessOption.UUID,
				Flow:           vlessOption.Flow,
				Network:        clashNetworks(vlessOption.UDP),
				Multiplex:      basicOption.SMUX.Build(),
				Transport:      clashTransport(vlessOption.Network, vlessOption.HTTPOpts, vlessOption.HTTP2Opts, vlessOption.GrpcOpts, vlessOption.WSOpts),
				PacketEncoding: &vlessOption.PacketEncoding,
			}
			options.TLS = clashTLSOptions(&option.OutboundTLSOptions{
				Enabled:    vlessOption.TLS,
				ServerName: vlessOption.ServerName,
				Insecure:   vlessOption.SkipCertVerify,
				ALPN:       vlessOption.ALPN,
				UTLS:       clashClientFingerprint(vlessOption.ClientFingerprint),
				ECH:        clashECHOptions(vlessOption.ECHOpts),
				Reality:    vlessOption.RealityOpts.Build(),
			})
			options.DialerOptions, options.ServerOptions = clashBasicOption(ctx, basicOption)
			outbound.Options = options
		case "socks5":
			socks5Option := &Socks5Option{}
			err = decoder.Decode(proxyMapping, socks5Option)
			if err != nil {
				return nil, E.Cause(err, "decode socks5 option", i)
			}
			outbound.Type = C.TypeSOCKS
			options := &option.SOCKSOutboundOptions{
				Username: socks5Option.UserName,
				Password: socks5Option.Password,
				Network:  clashNetworks(socks5Option.UDP),
			}
			options.DialerOptions, options.ServerOptions = clashBasicOption(ctx, basicOption)
			outbound.Options = options
		case "http":
			httpOption := &HttpOption{}
			err = decoder.Decode(proxyMapping, httpOption)
			if err != nil {
				return nil, E.Cause(err, "decode http option", i)
			}
			outbound.Type = C.TypeHTTP
			options := &option.HTTPOutboundOptions{
				Username: httpOption.UserName,
				Password: httpOption.Password,
			}
			options.DialerOptions, options.ServerOptions = clashBasicOption(ctx, basicOption)
			outbound.Options = options
		case "trojan":
			trojanOption := &TrojanOption{}
			err = decoder.Decode(proxyMapping, trojanOption)
			if err != nil {
				return nil, E.Cause(err, "decode trojan option", i)
			}
			outbound.Type = C.TypeTrojan
			options := &option.TrojanOutboundOptions{
				Password:  trojanOption.Password,
				Network:   clashNetworks(trojanOption.UDP),
				Multiplex: basicOption.SMUX.Build(),
				Transport: clashTransport(trojanOption.Network, HTTPOptions{}, HTTP2Options{}, trojanOption.GrpcOpts, trojanOption.WSOpts),
			}
			options.TLS = &option.OutboundTLSOptions{
				Enabled:    true,
				ServerName: trojanOption.SNI,
				Insecure:   trojanOption.SkipCertVerify,
				ALPN:       trojanOption.ALPN,
				UTLS:       clashClientFingerprint(trojanOption.ClientFingerprint),
				ECH:        clashECHOptions(trojanOption.ECHOpts),
				Reality:    trojanOption.RealityOpts.Build(),
			}
			options.DialerOptions, options.ServerOptions = clashBasicOption(ctx, basicOption)
			outbound.Options = options
		case "hysteria":
			hysteriaOption := &HysteriaOption{}
			err = decoder.Decode(proxyMapping, hysteriaOption)
			if err != nil {
				return nil, E.Cause(err, "decode hysteria option", i)
			}
			outbound.Type = C.TypeHysteria
			basicOption.TFO = hysteriaOption.FastOpen
			options := &option.HysteriaOutboundOptions{
				ServerPorts:         clashPorts(hysteriaOption.Ports),
				HopInterval:         badoption.Duration(hysteriaOption.HopInterval),
				Up:                  clashSpeedToNetworkBytes(hysteriaOption.Up),
				UpMbps:              hysteriaOption.UpSpeed,
				Down:                clashSpeedToNetworkBytes(hysteriaOption.Down),
				DownMbps:            hysteriaOption.DownSpeed,
				Obfs:                hysteriaOption.Obfs,
				Auth:                []byte(hysteriaOption.Auth),
				AuthString:          hysteriaOption.AuthString,
				ReceiveWindowConn:   uint64(hysteriaOption.ReceiveWindowConn),
				ReceiveWindow:       uint64(hysteriaOption.ReceiveWindow),
				DisableMTUDiscovery: hysteriaOption.DisableMTUDiscovery,
			}
			options.TLS = &option.OutboundTLSOptions{
				Enabled:         true,
				ServerName:      hysteriaOption.SNI,
				Insecure:        hysteriaOption.SkipCertVerify,
				ALPN:            hysteriaOption.ALPN,
				Certificate:     strings.Split(hysteriaOption.CustomCAString, "\n"),
				CertificatePath: hysteriaOption.CustomCA,
				ECH:             clashECHOptions(hysteriaOption.ECHOpts),
			}
			options.Up.UnmarshalJSON([]byte(hysteriaOption.Up))
			options.Down.UnmarshalJSON([]byte(hysteriaOption.Down))
			options.DialerOptions, options.ServerOptions = clashBasicOption(ctx, basicOption)
			outbound.Options = options
		case "hysteria2":
			hysteria2Option := &Hysteria2Option{}
			err = decoder.Decode(proxyMapping, hysteria2Option)
			if err != nil {
				return nil, E.Cause(err, "decode hysteria2 option", i)
			}
			outbound.Type = C.TypeHysteria
			options := &option.Hysteria2OutboundOptions{
				ServerPorts: clashPorts(hysteria2Option.Ports),
				HopInterval: badoption.Duration(hysteria2Option.HopInterval),
				UpMbps:      clashSpeedToIntMbps(hysteria2Option.Up),
				DownMbps:    clashSpeedToIntMbps(hysteria2Option.Down),
				Obfs:        clashHysteria2Obfs(hysteria2Option.Obfs, hysteria2Option.ObfsPassword),
				Password:    hysteria2Option.Password,
			}
			options.TLS = &option.OutboundTLSOptions{
				Enabled:         true,
				ServerName:      hysteria2Option.SNI,
				Insecure:        hysteria2Option.SkipCertVerify,
				ALPN:            hysteria2Option.ALPN,
				Certificate:     strings.Split(hysteria2Option.CustomCAString, "\n"),
				CertificatePath: hysteria2Option.CustomCA,
				ECH:             clashECHOptions(hysteria2Option.ECHOpts),
			}
			options.DialerOptions, options.ServerOptions = clashBasicOption(ctx, basicOption)
			outbound.Options = options
		}
		outbounds = append(outbounds, outbound)
	}
	return outbounds, nil
}

type RealityOptions struct {
	PublicKey string `proxy:"public-key"`
	ShortID   string `proxy:"short-id"`
}

func (r *RealityOptions) Build() *option.OutboundRealityOptions {
	if r == nil {
		return nil
	}
	return &option.OutboundRealityOptions{
		Enabled:   true,
		PublicKey: r.PublicKey,
		ShortID:   r.ShortID,
	}
}

type ECHOptions struct {
	Enable bool   `proxy:"enable,omitempty"`
	Config string `proxy:"config,omitempty"`
}

func (e *ECHOptions) Build() *option.OutboundECHOptions {
	if !e.Enable {
		return nil
	}
	list, err := base64.StdEncoding.DecodeString(e.Config)
	if err != nil {
		return nil
	}
	return &option.OutboundECHOptions{
		Enabled: true,
		Config:  strings.Split(string(list), "\n"),
	}
}

type HTTPOptions struct {
	Method  string              `proxy:"method,omitempty"`
	Path    []string            `proxy:"path,omitempty"`
	Headers map[string][]string `proxy:"headers,omitempty"`
}

type HTTP2Options struct {
	Host []string `proxy:"host,omitempty"`
	Path string   `proxy:"path,omitempty"`
}

type GrpcOptions struct {
	GrpcServiceName string `proxy:"grpc-service-name,omitempty"`
}

type WSOptions struct {
	Path                string            `proxy:"path,omitempty"`
	Headers             map[string]string `proxy:"headers,omitempty"`
	MaxEarlyData        int               `proxy:"max-early-data,omitempty"`
	EarlyDataHeaderName string            `proxy:"early-data-header-name,omitempty"`
	V2rayHttpUpgrade    bool              `proxy:"v2ray-http-upgrade,omitempty"`
}

type SingMuxOption struct {
	Enabled        bool         `proxy:"enabled,omitempty"`
	Protocol       string       `proxy:"protocol,omitempty"`
	MaxConnections int          `proxy:"max-connections,omitempty"`
	MinStreams     int          `proxy:"min-streams,omitempty"`
	MaxStreams     int          `proxy:"max-streams,omitempty"`
	Padding        bool         `proxy:"padding,omitempty"`
	BrutalOpts     BrutalOption `proxy:"brutal-opts,omitempty"`
}

func (s *SingMuxOption) Build() *option.OutboundMultiplexOptions {
	if s == nil || !s.Enabled {
		return nil
	}
	return &option.OutboundMultiplexOptions{
		Enabled:        true,
		Protocol:       s.Protocol,
		MaxConnections: s.MaxConnections,
		MinStreams:     s.MinStreams,
		MaxStreams:     s.MaxStreams,
		Padding:        s.Padding,
		Brutal:         s.BrutalOpts.Build(),
	}
}

type BrutalOption struct {
	Enabled bool   `proxy:"enabled,omitempty"`
	Up      string `proxy:"up,omitempty"`
	Down    string `proxy:"down,omitempty"`
}

func (b *BrutalOption) Build() *option.BrutalOptions {
	if b == nil || !b.Enabled {
		return nil
	}
	return &option.BrutalOptions{
		Enabled:  true,
		UpMbps:   clashSpeedToIntMbps(b.Up),
		DownMbps: clashSpeedToIntMbps(b.Down),
	}
}

type BasicOption struct {
	Name        string         `proxy:"name"`
	Server      string         `proxy:"server"`
	Type        string         `proxy:"type"`
	Port        int            `proxy:"port"`
	TFO         bool           `proxy:"tfo,omitempty"`
	MPTCP       bool           `proxy:"mptcp,omitempty"`
	Interface   string         `proxy:"interface-name,omitempty"`
	RoutingMark int            `proxy:"routing-mark,omitempty"`
	IPVersion   string         `proxy:"ip-version,omitempty"`
	DialerProxy string         `proxy:"dialer-proxy,omitempty"`
	SMUX        *SingMuxOption `proxy:"smux,omitempty"`
}

type ShadowSocksOption struct {
	Password          string         `proxy:"password"`
	Cipher            string         `proxy:"cipher"`
	UDP               bool           `proxy:"udp,omitempty"`
	Plugin            string         `proxy:"plugin,omitempty"`
	PluginOpts        map[string]any `proxy:"plugin-opts,omitempty"`
	UDPOverTCP        bool           `proxy:"udp-over-tcp,omitempty"`
	UDPOverTCPVersion int            `proxy:"udp-over-tcp-version,omitempty"`
	ClientFingerprint string         `proxy:"client-fingerprint,omitempty"`
}

type TuicOption struct {
	Token                string   `proxy:"token,omitempty"`
	UUID                 string   `proxy:"uuid,omitempty"`
	Password             string   `proxy:"password,omitempty"`
	Ip                   string   `proxy:"ip,omitempty"`
	HeartbeatInterval    int      `proxy:"heartbeat-interval,omitempty"`
	ALPN                 []string `proxy:"alpn,omitempty"`
	ReduceRtt            bool     `proxy:"reduce-rtt,omitempty"`
	UdpRelayMode         string   `proxy:"udp-relay-mode,omitempty"`
	CongestionController string   `proxy:"congestion-controller,omitempty"`
	DisableSni           bool     `proxy:"disable-sni,omitempty"`

	FastOpen            bool       `proxy:"fast-open,omitempty"`
	SkipCertVerify      bool       `proxy:"skip-cert-verify,omitempty"`
	CustomCA            string     `proxy:"ca,omitempty"`
	CustomCAString      string     `proxy:"ca-str,omitempty"`
	DisableMTUDiscovery bool       `proxy:"disable-mtu-discovery,omitempty"`
	SNI                 string     `proxy:"sni,omitempty"`
	ECHOpts             ECHOptions `proxy:"ech-opts,omitempty"`

	UDPOverStream bool `proxy:"udp-over-stream,omitempty"`
}

type VmessOption struct {
	UUID                string          `proxy:"uuid"`
	AlterID             int             `proxy:"alterId"`
	Cipher              string          `proxy:"cipher"`
	UDP                 bool            `proxy:"udp,omitempty"`
	Network             string          `proxy:"network,omitempty"`
	TLS                 bool            `proxy:"tls,omitempty"`
	ALPN                []string        `proxy:"alpn,omitempty"`
	SkipCertVerify      bool            `proxy:"skip-cert-verify,omitempty"`
	ServerName          string          `proxy:"servername,omitempty"`
	ECHOpts             ECHOptions      `proxy:"ech-opts,omitempty"`
	RealityOpts         *RealityOptions `proxy:"reality-opts,omitempty"`
	HTTPOpts            HTTPOptions     `proxy:"http-opts,omitempty"`
	HTTP2Opts           HTTP2Options    `proxy:"h2-opts,omitempty"`
	GrpcOpts            GrpcOptions     `proxy:"grpc-opts,omitempty"`
	WSOpts              WSOptions       `proxy:"ws-opts,omitempty"`
	PacketEncoding      string          `proxy:"packet-encoding,omitempty"`
	GlobalPadding       bool            `proxy:"global-padding,omitempty"`
	AuthenticatedLength bool            `proxy:"authenticated-length,omitempty"`
	ClientFingerprint   string          `proxy:"client-fingerprint,omitempty"`
}

type VlessOption struct {
	UUID              string            `proxy:"uuid"`
	Flow              string            `proxy:"flow,omitempty"`
	TLS               bool              `proxy:"tls,omitempty"`
	ALPN              []string          `proxy:"alpn,omitempty"`
	UDP               bool              `proxy:"udp,omitempty"`
	PacketAddr        bool              `proxy:"packet-addr,omitempty"`
	XUDP              bool              `proxy:"xudp,omitempty"`
	PacketEncoding    string            `proxy:"packet-encoding,omitempty"`
	Network           string            `proxy:"network,omitempty"`
	ECHOpts           ECHOptions        `proxy:"ech-opts,omitempty"`
	RealityOpts       *RealityOptions   `proxy:"reality-opts,omitempty"`
	HTTPOpts          HTTPOptions       `proxy:"http-opts,omitempty"`
	HTTP2Opts         HTTP2Options      `proxy:"h2-opts,omitempty"`
	GrpcOpts          GrpcOptions       `proxy:"grpc-opts,omitempty"`
	WSOpts            WSOptions         `proxy:"ws-opts,omitempty"`
	WSPath            string            `proxy:"ws-path,omitempty"`
	WSHeaders         map[string]string `proxy:"ws-headers,omitempty"`
	SkipCertVerify    bool              `proxy:"skip-cert-verify,omitempty"`
	ServerName        string            `proxy:"servername,omitempty"`
	ClientFingerprint string            `proxy:"client-fingerprint,omitempty"`
}

type TrojanOption struct {
	Name              string          `proxy:"name"`
	Server            string          `proxy:"server"`
	Port              int             `proxy:"port"`
	Password          string          `proxy:"password"`
	ALPN              []string        `proxy:"alpn,omitempty"`
	SNI               string          `proxy:"sni,omitempty"`
	SkipCertVerify    bool            `proxy:"skip-cert-verify,omitempty"`
	UDP               bool            `proxy:"udp,omitempty"`
	Network           string          `proxy:"network,omitempty"`
	ECHOpts           ECHOptions      `proxy:"ech-opts,omitempty"`
	RealityOpts       *RealityOptions `proxy:"reality-opts,omitempty"`
	GrpcOpts          GrpcOptions     `proxy:"grpc-opts,omitempty"`
	WSOpts            WSOptions       `proxy:"ws-opts,omitempty"`
	ClientFingerprint string          `proxy:"client-fingerprint,omitempty"`
}

type Socks5Option struct {
	UserName string `proxy:"username,omitempty"`
	Password string `proxy:"password,omitempty"`
	UDP      bool   `proxy:"udp,omitempty"`
}

type HttpOption struct {
	UserName string            `proxy:"username,omitempty"`
	Password string            `proxy:"password,omitempty"`
	Headers  map[string]string `proxy:"headers,omitempty"`
}

type HysteriaOption struct {
	Ports               string     `proxy:"ports,omitempty"`
	Up                  string     `proxy:"up"`
	UpSpeed             int        `proxy:"up-speed,omitempty"` // compatible with Stash
	Down                string     `proxy:"down"`
	DownSpeed           int        `proxy:"down-speed,omitempty"` // compatible with Stash
	Auth                string     `proxy:"auth,omitempty"`
	AuthString          string     `proxy:"auth-str,omitempty"`
	Obfs                string     `proxy:"obfs,omitempty"`
	SNI                 string     `proxy:"sni,omitempty"`
	ECHOpts             ECHOptions `proxy:"ech-opts,omitempty"`
	SkipCertVerify      bool       `proxy:"skip-cert-verify,omitempty"`
	ALPN                []string   `proxy:"alpn,omitempty"`
	CustomCA            string     `proxy:"ca,omitempty"`
	CustomCAString      string     `proxy:"ca-str,omitempty"`
	ReceiveWindowConn   int        `proxy:"recv-window-conn,omitempty"`
	ReceiveWindow       int        `proxy:"recv-window,omitempty"`
	DisableMTUDiscovery bool       `proxy:"disable-mtu-discovery,omitempty"`
	FastOpen            bool       `proxy:"fast-open,omitempty"`
	HopInterval         int        `proxy:"hop-interval,omitempty"`
}

type Hysteria2Option struct {
	Ports          string     `proxy:"ports,omitempty"`
	HopInterval    int        `proxy:"hop-interval,omitempty"`
	Up             string     `proxy:"up,omitempty"`
	Down           string     `proxy:"down,omitempty"`
	Password       string     `proxy:"password,omitempty"`
	Obfs           string     `proxy:"obfs,omitempty"`
	ObfsPassword   string     `proxy:"obfs-password,omitempty"`
	SNI            string     `proxy:"sni,omitempty"`
	ECHOpts        ECHOptions `proxy:"ech-opts,omitempty"`
	SkipCertVerify bool       `proxy:"skip-cert-verify,omitempty"`
	ALPN           []string   `proxy:"alpn,omitempty"`
	CustomCA       string     `proxy:"ca,omitempty"`
	CustomCAString string     `proxy:"ca-str,omitempty"`
}

func clashShadowsocksCipher(cipher string) string {
	switch cipher {
	case "dummy":
		return "none"
	}
	return cipher
}

func clashNetworks(udpEnabled bool) option.NetworkList {
	if !udpEnabled {
		return N.NetworkTCP
	}
	return ""
}

func clashPluginName(plugin string) string {
	switch plugin {
	case "obfs":
		return "obfs-local"
	}
	return plugin
}

type shadowsocksPluginOptionsBuilder map[string]any

func (o shadowsocksPluginOptionsBuilder) Build() string {
	var opts []string
	for key, value := range o {
		if value == nil {
			continue
		}
		opts = append(opts, F.ToString(key, "=", value))
	}
	return strings.Join(opts, ";")
}

func clashPluginOptions(plugin string, opts map[string]any) string {
	options := make(shadowsocksPluginOptionsBuilder)
	switch plugin {
	case "obfs":
		options["obfs"] = opts["mode"]
		options["obfs-host"] = opts["host"]
	case "v2ray-plugin":
		options["mode"] = opts["mode"]
		options["tls"] = opts["tls"]
		options["host"] = opts["host"]
		options["path"] = opts["path"]
	}
	return options.Build()
}

func clashTransport(network string, httpOpts HTTPOptions, h2Opts HTTP2Options, grpcOpts GrpcOptions, wsOpts WSOptions) *option.V2RayTransportOptions {
	switch network {
	case "http":
		var headers map[string]badoption.Listable[string]
		for key, values := range httpOpts.Headers {
			if headers == nil {
				headers = make(map[string]badoption.Listable[string])
			}
			headers[key] = values
		}
		return &option.V2RayTransportOptions{
			Type: C.V2RayTransportTypeHTTP,
			HTTPOptions: option.V2RayHTTPOptions{
				Method:  httpOpts.Method,
				Path:    clashStringList(httpOpts.Path),
				Headers: headers,
			},
		}
	case "h2":
		return &option.V2RayTransportOptions{
			Type: C.V2RayTransportTypeHTTP,
			HTTPOptions: option.V2RayHTTPOptions{
				Path: h2Opts.Path,
				Host: h2Opts.Host,
			},
		}
	case "grpc":
		return &option.V2RayTransportOptions{
			Type: C.V2RayTransportTypeGRPC,
			GRPCOptions: option.V2RayGRPCOptions{
				ServiceName: grpcOpts.GrpcServiceName,
			},
		}
	case "ws":
		var headers map[string]badoption.Listable[string]
		for key, value := range wsOpts.Headers {
			if headers == nil {
				headers = make(map[string]badoption.Listable[string])
			}
			headers[key] = []string{value}
		}
		if wsOpts.V2rayHttpUpgrade {
			var host string
			if headers["Host"] != nil && headers["Host"][0] != "" {
				host = headers["Host"][0]
			}
			return &option.V2RayTransportOptions{
				Type: C.V2RayTransportTypeHTTPUpgrade,
				HTTPUpgradeOptions: option.V2RayHTTPUpgradeOptions{
					Host:    host,
					Path:    wsOpts.Path,
					Headers: headers,
				},
			}
		}
		return &option.V2RayTransportOptions{
			Type: C.V2RayTransportTypeWebsocket,
			WebsocketOptions: option.V2RayWebsocketOptions{
				Path:                wsOpts.Path,
				Headers:             headers,
				MaxEarlyData:        uint32(wsOpts.MaxEarlyData),
				EarlyDataHeaderName: wsOpts.EarlyDataHeaderName,
			},
		}
	default:
		return nil
	}
}

func clashStringList(list []string) string {
	if len(list) > 0 {
		return list[0]
	}
	return ""
}

func clashTLSOptions(tlsOptions *option.OutboundTLSOptions) *option.OutboundTLSOptions {
	return tlsOptions
}

func clashClientFingerprint(clientFingerprint string) *option.OutboundUTLSOptions {
	if clientFingerprint == "" {
		return nil
	}
	return &option.OutboundUTLSOptions{
		Enabled:     true,
		Fingerprint: clientFingerprint,
	}
}

func clashECHOptions(echOptions ECHOptions) *option.OutboundECHOptions {
	if !echOptions.Enable {
		return nil
	}
	list, err := base64.StdEncoding.DecodeString(echOptions.Config)
	if err != nil {
		return nil
	}
	return &option.OutboundECHOptions{
		Enabled: true,
		Config:  strings.Split(string(list), "\n"),
	}
}

func clashPorts(ports string) badoption.Listable[string] {
	serverPorts := badoption.Listable[string]{}
	for _, port := range strings.Split(ports, ",") {
		if port == "" {
			continue
		}
		port = strings.Replace(port, "-", ":", 1)
		serverPorts = append(serverPorts, port)
	}
	return serverPorts
}

func clashIPVersion(ctx context.Context, ipVersion string) *option.DomainResolveOptions {
	if ipVersion == "" {
		return nil
	}
	networkManager := service.FromContext[adapter.NetworkManager](ctx)
	if networkManager == nil {
		return nil
	}
	domainResolveOptions := &option.DomainResolveOptions{}
	defaultOptions := networkManager.DefaultOptions()
	if defaultOptions.DomainResolver != "" {
		domainResolveOptions.Server = defaultOptions.DomainResolver
	} else {
		domainResolveOptions.Server = defaultOptions.DomainResolveOptions.Transport.Tag()
	}
	switch ipVersion {
	case "dual":
		domainResolveOptions.Strategy = option.DomainStrategy(C.DomainStrategyAsIS)
	case "ipv4":
		domainResolveOptions.Strategy = option.DomainStrategy(C.DomainStrategyIPv4Only)
	case "ipv6":
		domainResolveOptions.Strategy = option.DomainStrategy(C.DomainStrategyIPv6Only)
	case "ipv4-prefer":
		domainResolveOptions.Strategy = option.DomainStrategy(C.DomainStrategyPreferIPv4)
	case "ipv6-prefer":
		domainResolveOptions.Strategy = option.DomainStrategy(C.DomainStrategyPreferIPv6)
	}
	return domainResolveOptions
}

func clashBasicOption(ctx context.Context, basicOptions *BasicOption) (option.DialerOptions, option.ServerOptions) {
	return option.DialerOptions{
			Detour:         basicOptions.DialerProxy,
			BindInterface:  basicOptions.Interface,
			TCPFastOpen:    basicOptions.TFO,
			TCPMultiPath:   basicOptions.MPTCP,
			RoutingMark:    option.FwMark(basicOptions.RoutingMark),
			DomainResolver: clashIPVersion(ctx, basicOptions.IPVersion),
		}, option.ServerOptions{
			Server:     basicOptions.Server,
			ServerPort: uint16(basicOptions.Port),
		}
}

func clashSpeedToNetworkBytes(speed string) *byteformats.NetworkBytesCompat {
	if speed == "" {
		return nil
	}
	networkBytes := &byteformats.NetworkBytesCompat{}
	if num, err := strconv.Atoi(speed); err == nil {
		speed = F.ToString(num, "Mbps")
	}
	if err := networkBytes.UnmarshalJSON([]byte(speed)); err != nil {
		return nil
	}
	return networkBytes
}

func clashSpeedToIntMbps(speed string) int {
	if speed == "" {
		return 0
	}
	if num, err := strconv.Atoi(speed); err == nil {
		return num
	}
	networkBytes := byteformats.NetworkBytesCompat{}
	if err := networkBytes.UnmarshalJSON([]byte(speed)); err != nil {
		return 0
	}
	return int(networkBytes.Value() / byteformats.MByte / 8)
}

func clashHysteria2Obfs(obfs string, password string) *option.Hysteria2Obfs {
	if obfs == "" {
		return nil
	}
	return &option.Hysteria2Obfs{
		Type:     obfs,
		Password: password,
	}
}
