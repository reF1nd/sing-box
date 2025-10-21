package parser

import (
	"context"
	"encoding/base64"
	"net/http"
	"strconv"
	"strings"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/byteformats"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/json/badoption"
	N "github.com/sagernet/sing/common/network"

	"gopkg.in/yaml.v3"
)

type ClashListable[T any] badoption.Listable[T]

func (l *ClashListable[T]) UnmarshalYAML(value *yaml.Node) error {
	// 尝试解析为单个值
	var singleItem T
	if err := value.Decode(&singleItem); err == nil {
		*l = ClashListable[T]{singleItem}
		return nil
	}

	// 尝试解析为列表
	var list []T
	if err := value.Decode(&list); err != nil {
		return err
	}
	*l = list
	return nil
}

func (l ClashListable[T]) MarshalYAML() (interface{}, error) {
	if len(l) == 1 {
		return l[0], nil
	}
	return []T(l), nil
}

type ClashHTTPHeader map[string]ClashListable[string]

func (h ClashHTTPHeader) Build() http.Header {
	header := make(http.Header)
	for name, values := range h {
		for _, value := range values {
			header.Add(name, value)
		}
	}
	return header
}

func ConvertClashToHTTPHeader(clashHeader ClashHTTPHeader) badoption.HTTPHeader {
	httpHeader := make(badoption.HTTPHeader)
	for key, clashValues := range clashHeader {
		httpHeader[key] = badoption.Listable[string](clashValues)
	}
	return httpHeader
}

type ClashConfig struct {
	Proxies []ClashProxy `yaml:"proxies"`
}

type _ClashProxy struct {
	Name    string `yaml:"name"`
	Type    string `yaml:"type"`
	Options Proxy  `yaml:"-"`

	SingType string `yaml:"-"`
}
type ClashProxy _ClashProxy

func (c *ClashProxy) UnmarshalYAML(value *yaml.Node) error {
	err := value.Decode((*_ClashProxy)(c))
	if err != nil {
		return err
	}
	var options Proxy
	switch c.Type {
	case "ss":
		c.SingType = C.TypeShadowsocks
		options = &ShadowSocksOption{}
	case "tuic":
		c.SingType = C.TypeTUIC
		options = &TuicOption{}
	case "vmess":
		c.SingType = C.TypeVMess
		options = &VmessOption{}
	case "vless":
		c.SingType = C.TypeVLESS
		options = &VlessOption{}
	case "socks5":
		c.SingType = C.TypeSOCKS
		options = &Socks5Option{}
	case "http":
		c.SingType = C.TypeHTTP
		options = &HttpOption{}
	case "trojan":
		c.SingType = C.TypeTrojan
		options = &TrojanOption{}
	case "hysteria":
		c.SingType = C.TypeHysteria
		options = &HysteriaOption{}
	case "hysteria2":
		c.SingType = C.TypeHysteria2
		options = &Hysteria2Option{}
	case "ssh":
		c.SingType = C.TypeSSH
		options = &SSHOption{}
	case "anytls":
		c.SingType = C.TypeAnyTLS
		options = &AnyTLSOption{}
	default:
		return nil
	}
	err = value.Decode(options)
	if err != nil {
		return err
	}
	c.Options = options
	return nil
}

func (c *ClashProxy) Build() option.Outbound {
	outbound := option.Outbound{
		Tag:  c.Name,
		Type: c.SingType,
	}
	if c.Options != nil {
		outbound.Options = c.Options.Build()
	}
	return outbound
}

func ParseClashSubscription(_ context.Context, content string) ([]option.Outbound, error) {
	config := &ClashConfig{}
	err := yaml.Unmarshal([]byte(content), &config)
	if err != nil {
		return nil, E.Cause(err, "parse clash config")
	}
	outbounds := common.FilterIsInstance(config.Proxies, func(proxy ClashProxy) (option.Outbound, bool) {
		if proxy.SingType == "" {
			return option.Outbound{}, false
		}
		return proxy.Build(), true
	})
	return outbounds, nil
}

type HTTPOptions struct {
	Method  string               `yaml:"method,omitempty"`
	Path    []string             `yaml:"path,omitempty"`
	Headers badoption.HTTPHeader `yaml:"headers,omitempty"`
}

type HTTP2Options struct {
	Host []string `yaml:"host,omitempty"`
	Path string   `yaml:"path,omitempty"`
}

type GrpcOptions struct {
	GrpcServiceName string `yaml:"grpc-service-name,omitempty"`
}

type WSOptions struct {
	Path                string            `yaml:"path,omitempty"`
	Headers             map[string]string `yaml:"headers,omitempty"`
	MaxEarlyData        int               `yaml:"max-early-data,omitempty"`
	EarlyDataHeaderName string            `yaml:"early-data-header-name,omitempty"`
	V2rayHttpUpgrade    bool              `yaml:"v2ray-http-upgrade,omitempty"`
}

type MuxOption struct {
	Enabled        bool          `yaml:"enabled,omitempty"`
	Protocol       string        `yaml:"protocol,omitempty"`
	MaxConnections int           `yaml:"max-connections,omitempty"`
	MinStreams     int           `yaml:"min-streams,omitempty"`
	MaxStreams     int           `yaml:"max-streams,omitempty"`
	Padding        bool          `yaml:"padding,omitempty"`
	BrutalOpts     *BrutalOption `yaml:"brutal-opts,omitempty"`
}

func (s *MuxOption) Build() *option.OutboundMultiplexOptions {
	if s == nil {
		return nil
	}
	return &option.OutboundMultiplexOptions{
		Enabled:        s.Enabled,
		Protocol:       s.Protocol,
		MaxConnections: s.MaxConnections,
		MinStreams:     s.MinStreams,
		MaxStreams:     s.MaxStreams,
		Padding:        s.Padding,
		Brutal:         s.BrutalOpts.Build(),
	}
}

type BrutalOption struct {
	Enabled bool   `yaml:"enabled,omitempty"`
	Up      string `yaml:"up,omitempty"`
	Down    string `yaml:"down,omitempty"`
}

func (b *BrutalOption) Build() *option.BrutalOptions {
	if b == nil {
		return nil
	}
	return &option.BrutalOptions{
		Enabled:  b.Enabled,
		UpMbps:   clashSpeedToIntMbps(b.Up),
		DownMbps: clashSpeedToIntMbps(b.Down),
	}
}

type RealityOptions struct {
	PublicKey string `yaml:"public-key"`
	ShortID   string `yaml:"short-id"`
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
	Enable bool   `yaml:"enable,omitempty"`
	Config string `yaml:"config,omitempty"`
}

func (e *ECHOptions) Build() *option.OutboundECHOptions {
	if e == nil {
		return nil
	}
	list, err := base64.StdEncoding.DecodeString(e.Config)
	if err != nil {
		return nil
	}
	return &option.OutboundECHOptions{
		Enabled: e.Enable,
		Config:  trimStringArray(strings.Split(string(list), "\n")),
	}
}

type TLSOption struct {
	TLS               bool            `yaml:"tls,omitempty"`
	SNI               string          `yaml:"sni,omitempty"`
	ServerName        string          `yaml:"servername,omitempty"`
	SkipCertVerify    bool            `yaml:"skip-cert-verify,omitempty"`
	Fingerprint       string          `yaml:"fingerprint,omitempty"`
	ALPN              []string        `yaml:"alpn,omitempty"`
	ClientFingerprint string          `yaml:"client-fingerprint,omitempty"`
	CustomCA          string          `yaml:"ca,omitempty"`
	CustomCAString    string          `yaml:"ca-str,omitempty"`
	ECHOpts           *ECHOptions     `yaml:"ech-opts,omitempty"`
	RealityOpts       *RealityOptions `yaml:"reality-opts,omitempty"`
	KernelTx          bool            `yaml:"kernel-tx,omitempty"`
	KernelRx          bool            `yaml:"kernel-rx,omitempty"`
}

func (t *TLSOption) Build() *option.OutboundTLSOptions {
	if t == nil || !t.TLS {
		return nil
	}
	if t.SNI == "" {
		t.SNI = t.ServerName
	}
	return &option.OutboundTLSOptions{
		Enabled:              t.TLS,
		ServerName:           t.SNI,
		Insecure:             t.SkipCertVerify,
		CertificatePinSHA256: t.Fingerprint,
		ALPN:                 t.ALPN,
		UTLS:                 clashClientFingerprint(t.ClientFingerprint),
		Certificate:          trimStringArray(strings.Split(t.CustomCAString, "\n")),
		CertificatePath:      t.CustomCA,
		ECH:                  t.ECHOpts.Build(),
		Reality:              t.RealityOpts.Build(),
		KernelTx:             t.KernelTx,
		KernelRx:             t.KernelRx,
	}
}

type BasicOption struct {
	Server      string `yaml:"server"`
	Port        int    `yaml:"port"`
	TFO         bool   `yaml:"tfo,omitempty"`
	MPTCP       bool   `yaml:"mptcp,omitempty"`
	Interface   string `yaml:"interface-name,omitempty"`
	RoutingMark int    `yaml:"routing-mark,omitempty"`
	// IPVersion   string `yaml:"ip-version,omitempty"`
	DialerProxy string `yaml:"dialer-proxy,omitempty"`
}

type Proxy interface {
	Build() any
}

type ShadowSocksOption struct {
	BasicOption       `yaml:",inline"`
	*MuxOption        `yaml:",inline"`
	Password          string         `yaml:"password"`
	Cipher            string         `yaml:"cipher"`
	UDP               bool           `yaml:"udp,omitempty"`
	Plugin            string         `yaml:"plugin,omitempty"`
	PluginOpts        map[string]any `yaml:"plugin-opts,omitempty"`
	UDPOverTCP        bool           `yaml:"udp-over-tcp,omitempty"`
	UDPOverTCPVersion int            `yaml:"udp-over-tcp-version,omitempty"`
	MuxOpts           *MuxOption     `yaml:"smux,omitempty"`
}

func (s *ShadowSocksOption) Build() any {
	options := &option.ShadowsocksOutboundOptions{
		Password:      s.Password,
		Method:        clashShadowsocksCipher(s.Cipher),
		Plugin:        clashPluginName(s.Plugin),
		PluginOptions: clashPluginOptions(s.Plugin, s.PluginOpts),
		Network:       clashNetworks(s.UDP),
		UDPOverTCP: &option.UDPOverTCPOptions{
			Enabled: s.UDPOverTCP,
			Version: uint8(s.UDPOverTCPVersion),
		},
		Multiplex: s.MuxOpts.Build(),
	}
	options.DialerOptions, options.ServerOptions = clashBasicOption(s.BasicOption)
	return options
}

type TuicOption struct {
	BasicOption          `yaml:",inline"`
	TLSOption            `yaml:",inline"`
	UUID                 string `yaml:"uuid,omitempty"`
	Password             string `yaml:"password,omitempty"`
	Ip                   string `yaml:"ip,omitempty"`
	HeartbeatInterval    int    `yaml:"heartbeat-interval,omitempty"`
	DisableSni           bool   `yaml:"disable-sni,omitempty"`
	ReduceRtt            bool   `yaml:"reduce-rtt,omitempty"`
	UdpRelayMode         string `yaml:"udp-relay-mode,omitempty"`
	CongestionController string `yaml:"congestion-controller,omitempty"`
	FastOpen             bool   `yaml:"fast-open,omitempty"`
	DisableMTUDiscovery  bool   `yaml:"disable-mtu-discovery,omitempty"`

	UDPOverStream bool `yaml:"udp-over-stream,omitempty"`
}

func (t *TuicOption) Build() any {
	options := &option.TUICOutboundOptions{
		UUID:              t.UUID,
		Password:          t.Password,
		CongestionControl: t.CongestionController,
		UDPRelayMode:      t.UdpRelayMode,
		UDPOverStream:     t.UDPOverStream,
		ZeroRTTHandshake:  t.ReduceRtt,
		Heartbeat:         badoption.Duration(t.HeartbeatInterval),
	}
	t.TLS = true
	t.TFO = t.FastOpen
	options.TLS = t.TLSOption.Build()
	options.DialerOptions, options.ServerOptions = clashBasicOption(t.BasicOption)
	return options
}

type VmessOption struct {
	BasicOption         `yaml:",inline"`
	*TLSOption          `yaml:",inline"`
	UUID                string       `yaml:"uuid"`
	AlterID             int          `yaml:"alterId"`
	Cipher              string       `yaml:"cipher"`
	UDP                 bool         `yaml:"udp,omitempty"`
	Network             string       `yaml:"network,omitempty"`
	HTTPOpts            HTTPOptions  `yaml:"http-opts,omitempty"`
	HTTP2Opts           HTTP2Options `yaml:"h2-opts,omitempty"`
	GrpcOpts            GrpcOptions  `yaml:"grpc-opts,omitempty"`
	WSOpts              WSOptions    `yaml:"ws-opts,omitempty"`
	PacketEncoding      string       `yaml:"packet-encoding,omitempty"`
	GlobalPadding       bool         `yaml:"global-padding,omitempty"`
	AuthenticatedLength bool         `yaml:"authenticated-length,omitempty"`
	MuxOpts             *MuxOption   `yaml:"smux,omitempty"`
}

func (v *VmessOption) Build() any {
	options := &option.VMessOutboundOptions{
		UUID:                v.UUID,
		Security:            v.Cipher,
		AlterId:             v.AlterID,
		GlobalPadding:       v.GlobalPadding,
		AuthenticatedLength: v.AuthenticatedLength,
		Network:             clashNetworks(v.UDP),
		PacketEncoding:      v.PacketEncoding,
		Multiplex:           v.MuxOpts.Build(),
		Transport:           clashTransport(v.Network, v.HTTPOpts, v.HTTP2Opts, v.GrpcOpts, v.WSOpts),
	}
	options.TLS = v.TLSOption.Build()
	options.DialerOptions, options.ServerOptions = clashBasicOption(v.BasicOption)
	return options
}

type VlessOption struct {
	BasicOption    `yaml:",inline"`
	*TLSOption     `yaml:",inline"`
	UUID           string            `yaml:"uuid"`
	Flow           string            `yaml:"flow,omitempty"`
	UDP            bool              `yaml:"udp,omitempty"`
	PacketAddr     bool              `yaml:"packet-addr,omitempty"`
	XUDP           bool              `yaml:"xudp,omitempty"`
	PacketEncoding string            `yaml:"packet-encoding,omitempty"`
	Network        string            `yaml:"network,omitempty"`
	HTTPOpts       HTTPOptions       `yaml:"http-opts,omitempty"`
	HTTP2Opts      HTTP2Options      `yaml:"h2-opts,omitempty"`
	GrpcOpts       GrpcOptions       `yaml:"grpc-opts,omitempty"`
	WSOpts         WSOptions         `yaml:"ws-opts,omitempty"`
	WSPath         string            `yaml:"ws-path,omitempty"`
	WSHeaders      map[string]string `yaml:"ws-headers,omitempty"`
	MuxOpts        *MuxOption        `yaml:"smux,omitempty"`
}

func (v *VlessOption) Build() any {
	options := &option.VLESSOutboundOptions{
		UUID:           v.UUID,
		Flow:           v.Flow,
		Network:        clashNetworks(v.UDP),
		Multiplex:      v.MuxOpts.Build(),
		Transport:      clashTransport(v.Network, v.HTTPOpts, v.HTTP2Opts, v.GrpcOpts, v.WSOpts),
		PacketEncoding: &v.PacketEncoding,
	}
	options.TLS = v.TLSOption.Build()
	options.DialerOptions, options.ServerOptions = clashBasicOption(v.BasicOption)
	return options
}

type Socks5Option struct {
	BasicOption `yaml:",inline"`
	UserName    string `yaml:"username,omitempty"`
	Password    string `yaml:"password,omitempty"`
	UDP         bool   `yaml:"udp,omitempty"`
}

func (s *Socks5Option) Build() any {
	options := &option.SOCKSOutboundOptions{
		Username: s.UserName,
		Password: s.Password,
		Network:  clashNetworks(s.UDP),
	}
	options.DialerOptions, options.ServerOptions = clashBasicOption(s.BasicOption)
	return options
}

type HttpOption struct {
	BasicOption `yaml:",inline"`
	*TLSOption  `yaml:",inline"`
	UserName    string          `yaml:"username,omitempty"`
	Password    string          `yaml:"password,omitempty"`
	Headers     ClashHTTPHeader `yaml:"headers,omitempty"`
}

func (h *HttpOption) Build() any {
	options := &option.HTTPOutboundOptions{
		Username: h.UserName,
		Password: h.Password,
		Headers:  ConvertClashToHTTPHeader(h.Headers),
	}
	options.TLS = h.TLSOption.Build()
	options.DialerOptions, options.ServerOptions = clashBasicOption(h.BasicOption)
	return options
}

type TrojanOption struct {
	BasicOption `yaml:",inline"`
	TLSOption   `yaml:",inline"`
	Password    string      `yaml:"password"`
	UDP         bool        `yaml:"udp,omitempty"`
	Network     string      `yaml:"network,omitempty"`
	GrpcOpts    GrpcOptions `yaml:"grpc-opts,omitempty"`
	WSOpts      WSOptions   `yaml:"ws-opts,omitempty"`
	MuxOpts     *MuxOption  `yaml:"smux,omitempty"`
}

func (t *TrojanOption) Build() any {
	options := &option.TrojanOutboundOptions{
		Password:  t.Password,
		Network:   clashNetworks(t.UDP),
		Multiplex: t.MuxOpts.Build(),
		Transport: clashTransport(t.Network, HTTPOptions{}, HTTP2Options{}, t.GrpcOpts, t.WSOpts),
	}
	t.TLS = true
	options.TLS = t.TLSOption.Build()
	options.DialerOptions, options.ServerOptions = clashBasicOption(t.BasicOption)
	return options
}

type HysteriaOption struct {
	BasicOption         `yaml:",inline"`
	TLSOption           `yaml:",inline"`
	Ports               string `yaml:"ports,omitempty"`
	Up                  string `yaml:"up"`
	UpSpeed             int    `yaml:"up-speed,omitempty"` // compatible with Stash
	Down                string `yaml:"down"`
	DownSpeed           int    `yaml:"down-speed,omitempty"` // compatible with Stash
	Auth                string `yaml:"auth,omitempty"`
	AuthString          string `yaml:"auth-str,omitempty"`
	Obfs                string `yaml:"obfs,omitempty"`
	ReceiveWindowConn   int    `yaml:"recv-window-conn,omitempty"`
	ReceiveWindow       int    `yaml:"recv-window,omitempty"`
	DisableMTUDiscovery bool   `yaml:"disable-mtu-discovery,omitempty"`
	FastOpen            bool   `yaml:"fast-open,omitempty"`
	HopInterval         int    `yaml:"hop-interval,omitempty"`
}

func (h *HysteriaOption) Build() any {
	options := &option.HysteriaOutboundOptions{
		ServerPorts:         clashPorts(h.Ports),
		HopInterval:         badoption.Duration(h.HopInterval),
		Up:                  clashSpeedToNetworkBytes(h.Up),
		UpMbps:              h.UpSpeed,
		Down:                clashSpeedToNetworkBytes(h.Down),
		DownMbps:            h.DownSpeed,
		Obfs:                h.Obfs,
		Auth:                []byte(h.Auth),
		AuthString:          h.AuthString,
		ReceiveWindowConn:   uint64(h.ReceiveWindowConn),
		ReceiveWindow:       uint64(h.ReceiveWindow),
		DisableMTUDiscovery: h.DisableMTUDiscovery,
	}
	h.TLS = true
	h.TFO = h.FastOpen
	options.TLS = h.TLSOption.Build()
	options.DialerOptions, options.ServerOptions = clashBasicOption(h.BasicOption)
	return options
}

type Hysteria2Option struct {
	BasicOption  `yaml:",inline"`
	TLSOption    `yaml:",inline"`
	Ports        string `yaml:"ports,omitempty"`
	HopInterval  int    `yaml:"hop-interval,omitempty"`
	Up           string `yaml:"up,omitempty"`
	Down         string `yaml:"down,omitempty"`
	Password     string `yaml:"password,omitempty"`
	Obfs         string `yaml:"obfs,omitempty"`
	ObfsPassword string `yaml:"obfs-password,omitempty"`
}

func (h *Hysteria2Option) Build() any {
	options := &option.Hysteria2OutboundOptions{
		ServerPorts: clashPorts(h.Ports),
		HopInterval: badoption.Duration(h.HopInterval),
		UpMbps:      clashSpeedToIntMbps(h.Up),
		DownMbps:    clashSpeedToIntMbps(h.Down),
		Obfs:        clashHysteria2Obfs(h.Obfs, h.ObfsPassword),
		Password:    h.Password,
	}
	h.TLS = true
	options.TLS = h.TLSOption.Build()
	options.DialerOptions, options.ServerOptions = clashBasicOption(h.BasicOption)
	return options
}

type SSHOption struct {
	BasicOption          `yaml:",inline"`
	UserName             string   `yaml:"username"`
	Password             string   `yaml:"password,omitempty"`
	PrivateKey           string   `yaml:"private-key,omitempty"`
	PrivateKeyPassphrase string   `yaml:"private-key-passphrase,omitempty"`
	HostKey              []string `yaml:"host-key,omitempty"`
	HostKeyAlgorithms    []string `yaml:"host-key-algorithms,omitempty"`
}

func (s *SSHOption) Build() any {
	options := &option.SSHOutboundOptions{
		User:                 s.UserName,
		Password:             s.Password,
		PrivateKeyPassphrase: s.PrivateKeyPassphrase,
		HostKey:              s.HostKey,
		HostKeyAlgorithms:    s.HostKeyAlgorithms,
	}
	if strings.Contains(s.PrivateKey, "PRIVATE KEY") {
		options.PrivateKey = trimStringArray(strings.Split(s.PrivateKey, "\n"))
	} else {
		options.PrivateKeyPath = s.PrivateKey
	}
	options.DialerOptions, options.ServerOptions = clashBasicOption(s.BasicOption)
	return options
}

type AnyTLSOption struct {
	BasicOption              `yaml:",inline"`
	TLSOption                `yaml:",inline"`
	Password                 string `yaml:"password"`
	UDP                      bool   `yaml:"udp,omitempty"`
	IdleSessionCheckInterval int    `yaml:"idle-session-check-interval,omitempty"`
	IdleSessionTimeout       int    `yaml:"idle-session-timeout,omitempty"`
	MinIdleSession           int    `yaml:"min-idle-session,omitempty"`
}

func (a *AnyTLSOption) Build() any {
	options := &option.AnyTLSOutboundOptions{
		Password:                 a.Password,
		IdleSessionCheckInterval: badoption.Duration(a.IdleSessionCheckInterval),
		IdleSessionTimeout:       badoption.Duration(a.IdleSessionTimeout),
		MinIdleSession:           a.MinIdleSession,
	}
	a.TLS = true
	options.TLS = a.TLSOption.Build()
	options.DialerOptions, options.ServerOptions = clashBasicOption(a.BasicOption)
	return options
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
		return &option.V2RayTransportOptions{
			Type: C.V2RayTransportTypeHTTP,
			HTTPOptions: option.V2RayHTTPOptions{
				Method:  httpOpts.Method,
				Path:    clashStringList(httpOpts.Path),
				Headers: httpOpts.Headers,
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

func clashClientFingerprint(clientFingerprint string) *option.OutboundUTLSOptions {
	if clientFingerprint == "" {
		return nil
	}
	return &option.OutboundUTLSOptions{
		Enabled:     true,
		Fingerprint: clientFingerprint,
	}
}

func clashPorts(ports string) badoption.Listable[string] {
	if ports == "" {
		return nil
	}
	serverPorts := badoption.Listable[string]{}
	ports = strings.ReplaceAll(ports, "/", ",")
	for _, port := range strings.Split(ports, ",") {
		if port == "" {
			continue
		}
		port = strings.Replace(port, "-", ":", 1)
		serverPorts = append(serverPorts, port)
	}
	return serverPorts
}

func clashBasicOption(basicOptions BasicOption) (option.DialerOptions, option.ServerOptions) {
	return option.DialerOptions{
			Detour:        basicOptions.DialerProxy,
			BindInterface: basicOptions.Interface,
			TCPFastOpen:   basicOptions.TFO,
			TCPMultiPath:  basicOptions.MPTCP,
			RoutingMark:   option.FwMark(basicOptions.RoutingMark),
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

func trimStringArray(array []string) []string {
	return common.Filter(array, func(it string) bool {
		return strings.TrimSpace(it) != ""
	})
}
