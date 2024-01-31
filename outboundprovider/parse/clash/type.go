package clash

import (
	"fmt"
	"strconv"

	"github.com/sagernet/sing-box/option"

	"gopkg.in/yaml.v3"
)

type ClashProxyInterface interface {
	Tag() string
	GenerateOptions() (*option.Outbound, error)
}

type ClashConfig struct {
	Proxies []ClashProxy `yaml:"proxies"`
}

const (
	ClashTypeHTTP        = "http"
	ClashTypeSocks5      = "socks5"
	ClashTypeShadowsocks = "ss"
	ClashTypeVMess       = "vmess"
	ClashTypeTrojan      = "trojan"
	ClashTypeVLESS       = "vless"
	ClashTypeHysteria    = "hysteria"
	ClashTypeHysteria2   = "hysteria2"
	ClashTypeTUIC        = "tuic"
)

type Port uint16

func (p *Port) UnmarshalYAML(node *yaml.Node) error {
	var port uint16
	err := node.Decode(&port)
	if err == nil {
		*p = Port(port)
		return nil
	}
	var portStr string
	err2 := node.Decode(&portStr)
	if err2 != nil {
		return err
	}
	portUint64, err3 := strconv.ParseUint(portStr, 10, 16)
	if err3 != nil {
		return err
	}
	*p = Port(portUint64)
	return nil
}

type ClashProxyBasic struct {
	Name       string `yaml:"name"`
	Type       string `yaml:"type"`
	Server     string `yaml:"server"`
	ServerPort Port   `yaml:"port"`
	//
	IPVersion string `yaml:"ip-version,omitempty"`
}

type ClashProxy struct {
	Type  string
	Proxy ClashProxyInterface
}

type ClashProxyPre struct {
	Type string `yaml:"type"`
}

func (c *ClashProxy) UnmarshalYAML(node *yaml.Node) error {
	var pre ClashProxyPre
	err := node.Decode(&pre)
	if err != nil {
		return err
	}
	switch pre.Type {
	case ClashTypeHTTP:
		c.Proxy = &ClashHTTP{}
	case ClashTypeSocks5:
		c.Proxy = &ClashSocks{}
	case ClashTypeShadowsocks:
		c.Proxy = &ClashShadowsocks{}
	case ClashTypeVMess:
		c.Proxy = &ClashVMess{}
	case ClashTypeVLESS:
		c.Proxy = &ClashVLESS{}
	case ClashTypeTrojan:
		c.Proxy = &ClashTrojan{}
	case ClashTypeHysteria:
		c.Proxy = &ClashHysteria{}
	case ClashTypeHysteria2:
		c.Proxy = &ClashHysteria2{}
	case ClashTypeTUIC:
		c.Proxy = &ClashTUIC{}
	default:
		return fmt.Errorf("unknown clash proxy type: %s", pre.Type)
	}
	err = node.Decode(c.Proxy)
	return err
}

func ParseClashConfig(raw []byte) ([]option.Outbound, error) {
	var config ClashConfig
	err := yaml.Unmarshal(raw, &config)
	if err != nil {
		return nil, err
	}
	if config.Proxies == nil || len(config.Proxies) == 0 {
		return nil, fmt.Errorf("no outbounds found in clash config")
	}
	m := make([]option.Outbound, 0, len(config.Proxies))
	for i, proxy := range config.Proxies {
		options, err := proxy.Proxy.GenerateOptions()
		if err != nil {
			return nil, fmt.Errorf("parse outbound[%d], tag: `%s` failed: %s", i+1, proxy.Proxy.Tag(), err)
		}
		m = append(m, *options)
	}
	return m, nil
}
