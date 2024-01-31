package raw

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/outboundprovider/parse/utils"
)

type Shadowsocks struct {
	options *option.Outbound
}

func (p *Shadowsocks) Tag() string {
	return p.options.Tag
}

func (p *Shadowsocks) ParseLink(link string) error {
	sLink := link
	tryOk, tryErr := func() (bool, error) {
		// tryParseLink
		func() {
			_sLink := strings.TrimPrefix(sLink, "ss://")
			suri := strings.SplitAfterN(_sLink, "#", 2)
			var sLabel string
			if len(suri) <= 2 {
				if len(suri) == 2 {
					sLabel = "#" + suri[1]
				}
				l, err := base64.RawURLEncoding.DecodeString(suri[0])
				if err != nil {
					return
				}
				sLink = "ss://" + string(l) + sLabel
			}
		}()
		// SIP002 format https://shadowsocks.org/guide/sip002.html
		u, err := url.Parse(sLink)
		if err != nil {
			return false, nil
		}
		var port uint16
		portStr := u.Port()
		if portStr != "" {
			portUint64, err := strconv.ParseUint(u.Port(), 10, 16)
			if err != nil {
				return false, nil
			}
			if portUint64 == 0 || portUint64 > 0xffff {
				return false, nil
			}
			port = uint16(portUint64)
		} else {
			port = 1080
		}
		method := u.User.Username()
		password, ok := u.User.Password()
		if !ok {
			s, err := base64.RawURLEncoding.DecodeString(method)
			if err != nil {
				return false, nil
			}
			ss := strings.SplitN(string(s), ":", 2)
			if len(ss) != 2 {
				return false, nil
			}
			method = ss[0]
			password = ss[1]
		}
		if !utils.CheckShadowsocksMethod(method) {
			return false, fmt.Errorf("parse link `%s` failed: invalid method: %s", link, method)
		}
		options := &option.Outbound{
			Type: C.TypeShadowsocks,
			ShadowsocksOptions: option.ShadowsocksOutboundOptions{
				ServerOptions: option.ServerOptions{
					Server:     u.Hostname(),
					ServerPort: port,
				},
				Method:   method,
				Password: password,
			},
		}
		args, err := url.ParseQuery(u.RawQuery)
		if err == nil {
			plugin := args.Get("plugin")
			if plugin != "" {
				plugins := strings.SplitN(plugin, ";", 2)
				options.ShadowsocksOptions.Plugin = plugins[0]
				if len(plugins) == 2 {
					options.ShadowsocksOptions.PluginOptions = plugins[1]
				}
			}
		}
		if u.Fragment != "" {
			options.Tag = u.Fragment
		} else {
			options.Tag = net.JoinHostPort(options.ShadowsocksOptions.Server, strconv.Itoa(int(options.ShadowsocksOptions.ServerPort)))
		}
		p.options = options
		return true, nil
	}()
	if tryOk {
		return nil
	}
	if tryErr != nil {
		return tryErr
	}
	sLink = strings.TrimPrefix(sLink, "ss://")
	sLinks := strings.SplitAfterN(sLink, "#", 2)
	sLink = sLinks[0]
	var tag string
	if len(sLinks) == 2 {
		tag = sLinks[1]
	}
	uri := strings.SplitAfterN(sLink, "@", 2)
	if len(uri) != 2 {
		return fmt.Errorf("parse link `%s` failed", link)
	}
	us := strings.SplitN(uri[0], ":", 2)
	if len(us) != 2 {
		return fmt.Errorf("parse link `%s` failed", link)
	}
	method := us[0]
	if !utils.CheckShadowsocksMethod(method) {
		return fmt.Errorf("parse link `%s` failed: invalid method: %s", link, method)
	}
	password := us[1]
	host, portStr, err := net.SplitHostPort(uri[1])
	if err != nil {
		return fmt.Errorf("parse link `%s` failed: invalid address, error: %s", link, err)
	}
	if host == "" {
		return fmt.Errorf("parse link `%s` failed: invalid address", link)
	}
	portUint64, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return fmt.Errorf("parse link `%s` failed: invalid port: `%s`, error: %s", link, portStr, err)
	}
	port := uint16(portUint64)
	options := &option.Outbound{
		Type: C.TypeShadowsocks,
		ShadowsocksOptions: option.ShadowsocksOutboundOptions{
			ServerOptions: option.ServerOptions{
				Server:     host,
				ServerPort: port,
			},
			Method:   method,
			Password: password,
		},
	}
	if tag != "" {
		options.Tag = tag
	} else {
		options.Tag = net.JoinHostPort(options.ShadowsocksOptions.Server, strconv.Itoa(int(options.ShadowsocksOptions.ServerPort)))
	}
	p.options = options
	return nil
}

func (p *Shadowsocks) Options() *option.Outbound {
	return p.options
}
