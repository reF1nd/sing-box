package clash

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/outboundprovider/parse/utils"
)

type ClashShadowsocks struct {
	ClashProxyBasic `yaml:",inline"`
	//
	Cipher   string `yaml:"cipher"`
	Password string `yaml:"password"`
	//
	Plugin            string         `yaml:"plugin"`
	PluginOpts        map[string]any `yaml:"plugin-opts"`
	UDP               *bool          `yaml:"udp"`
	UDPOverTCP        bool           `yaml:"udp-over-tcp"`
	UDPOverTCPVersion uint8          `yaml:"udp-over-tcp-version,omitempty"`
	//
	TFO bool `yaml:"tfo,omitempty"`
	//
	MuxOptions *ClashSingMuxOptions `yaml:"smux,omitempty"`
}

func (c *ClashShadowsocks) Tag() string {
	if c.ClashProxyBasic.Name == "" {
		c.ClashProxyBasic.Name = net.JoinHostPort(c.ClashProxyBasic.Server, strconv.Itoa(int(c.ClashProxyBasic.ServerPort)))
	}
	return c.ClashProxyBasic.Name
}

func (c *ClashShadowsocks) GenerateOptions() (*option.Outbound, error) {
	outboundOptions := &option.Outbound{
		Tag:  c.Tag(),
		Type: C.TypeShadowsocks,
		ShadowsocksOptions: option.ShadowsocksOutboundOptions{
			ServerOptions: option.ServerOptions{
				Server:     c.ClashProxyBasic.Server,
				ServerPort: uint16(c.ClashProxyBasic.ServerPort),
			},
			Method:   c.Cipher,
			Password: c.Password,
		},
	}
	if !utils.CheckShadowsocksMethod(c.Cipher) {
		return nil, fmt.Errorf("unsupported cipher: %s", c.Cipher)
	}

	switch c.Plugin {
	case "":
	case "obfs":
		obfsOptions := make(map[string][]string)
		modeAny, ok := c.PluginOpts["mode"]
		if ok {
			mode, ok := modeAny.(string)
			if ok {
				obfsOptions["obfs"] = []string{mode}
			}
		}
		hostAny, ok := c.PluginOpts["host"]
		if ok {
			host, ok := hostAny.(string)
			if ok {
				obfsOptions["obfs-host"] = []string{host}
			}
		}
		pluginOptsStr := encodeSmethodArgs(obfsOptions)
		outboundOptions.ShadowsocksOptions.Plugin = "obfs-local"
		outboundOptions.ShadowsocksOptions.PluginOptions = pluginOptsStr
	case "v2ray-plugin":
		return nil, errors.New("v2ray-plugin is not supported")
	default:
		return nil, fmt.Errorf("unsupported plugin: %s", c.Plugin)
	}

	if c.UDP != nil && !*c.UDP {
		outboundOptions.ShadowsocksOptions.Network = option.NetworkList("tcp")
	}
	if c.UDPOverTCP {
		outboundOptions.ShadowsocksOptions.UDPOverTCP = &option.UDPOverTCPOptions{
			Enabled: true,
			Version: c.UDPOverTCPVersion,
		}
	}

	if c.TFO {
		outboundOptions.ShadowsocksOptions.TCPFastOpen = true
	}

	if c.MuxOptions != nil && c.MuxOptions.Enabled {
		outboundOptions.ShadowsocksOptions.Multiplex = &option.OutboundMultiplexOptions{
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
		outboundOptions.ShadowsocksOptions.DomainStrategy = 0
	case "ipv4":
		outboundOptions.ShadowsocksOptions.DomainStrategy = 3
	case "ipv6":
		outboundOptions.ShadowsocksOptions.DomainStrategy = 4
	case "ipv4-prefer":
		outboundOptions.ShadowsocksOptions.DomainStrategy = 1
	case "ipv6-prefer":
		outboundOptions.ShadowsocksOptions.DomainStrategy = 2
	}

	return outboundOptions, nil
}

func backslashEscape(s string, set []byte) string {
	var buf bytes.Buffer
	for _, b := range []byte(s) {
		if b == '\\' || bytes.IndexByte(set, b) != -1 {
			buf.WriteByte('\\')
		}
		buf.WriteByte(b)
	}
	return buf.String()
}

func encodeSmethodArgs(args map[string][]string) string {
	if args == nil {
		return ""
	}

	keys := make([]string, 0, len(args))
	for key := range args {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	escape := func(s string) string {
		return backslashEscape(s, []byte{'=', ','})
	}

	var pairs []string
	for _, key := range keys {
		for _, value := range args[key] {
			pairs = append(pairs, escape(key)+"="+escape(value))
		}
	}

	return strings.Join(pairs, ";")
}
