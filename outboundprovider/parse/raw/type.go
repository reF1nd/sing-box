package raw

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/sagernet/sing-box/option"
)

// From Homeproxy

type RawInterface interface {
	Tag() string
	ParseLink(link string) error
	Options() *option.Outbound
}

func base64Decode(b64 string) ([]byte, error) {
	b64 = strings.TrimSpace(b64)
	stdb64 := b64
	if pad := len(b64) % 4; pad != 0 {
		stdb64 += strings.Repeat("=", 4-pad)
	}

	b, err := base64.StdEncoding.DecodeString(stdb64)
	if err != nil {
		return base64.URLEncoding.DecodeString(b64)
	}
	return b, nil
}

func ParseRawConfig(raw []byte) ([]option.Outbound, error) {
	rawStr := string(raw)
	_raw, err := base64Decode(rawStr)
	if err != nil {
		return nil, err
	} else {
		rawStr = string(_raw)
	}
	rawList := strings.Split(rawStr, "\n")
	var peerList []option.Outbound
	for i, r := range rawList {
		rs := string(r)
		rs = strings.TrimSpace(rs)
		if rs == "" {
			continue
		}
		ss := strings.SplitN(rs, "://", 2)
		if len(ss) != 2 {
			continue
		}
		head := ss[0]
		var peer RawInterface
		switch head {
		case "http", "https":
			peer = &HTTP{}
		case "socks", "socks4", "socks4a", "socks5", "socks5h":
			peer = &Socks{}
		case "hysteria":
			peer = &Hysteria{}
		case "hy2", "hysteria2":
			peer = &Hysteria2{}
		case "ss":
			peer = &Shadowsocks{}
		case "trojan":
			peer = &Trojan{}
		case "vmess":
			peer = &VMess{}
		case "vless":
			peer = &VLESS{}
		case "tuic":
			peer = &Tuic{}
		default:
			continue
		}
		err = peer.ParseLink(head + "://" + ss[1])
		if err != nil {
			return nil, fmt.Errorf("parse proxy[%d] failed: %s", i+1, err)
		}
		peerList = append(peerList, *peer.Options())
	}
	if len(peerList) == 0 {
		return nil, fmt.Errorf("no outbounds found in raw link")
	}
	return peerList, nil
}

func ParseRawLink(link string) (*option.Outbound, error) {
	ss := strings.SplitN(link, "://", 2)
	if len(ss) != 2 {
		return nil, fmt.Errorf("invalid link")
	}
	head := ss[0]
	var peer RawInterface
	switch head {
	case "http", "https":
		peer = &HTTP{}
	case "socks", "socks4", "socks4a", "socks5", "socks5h":
		peer = &Socks{}
	case "hysteria":
		peer = &Hysteria{}
	case "hy2", "hysteria2":
		peer = &Hysteria2{}
	case "ss":
		peer = &Shadowsocks{}
	case "trojan":
		peer = &Trojan{}
	case "vmess":
		peer = &VMess{}
	case "vless":
		peer = &VLESS{}
	case "tuic":
		peer = &Tuic{}
	default:
		return nil, fmt.Errorf("invalid link: unsupport protocol: %s", head)
	}
	err := peer.ParseLink(head + "://" + ss[1])
	if err != nil {
		return nil, fmt.Errorf("parse failed: %s", err)
	}
	return peer.Options(), nil
}
