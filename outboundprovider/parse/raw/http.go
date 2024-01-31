package raw

import (
	"fmt"
	"net"
	"net/url"
	"strconv"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

type HTTP struct {
	options *option.Outbound
}

func (p *HTTP) Tag() string {
	return p.options.Tag
}

func (p *HTTP) ParseLink(link string) error {
	u, err := url.Parse(link)
	if err != nil {
		return fmt.Errorf("parse link `%s` failed: %w", link, err)
	}
	var port uint16
	portStr := u.Port()
	if portStr != "" {
		portUint64, err := strconv.ParseUint(u.Port(), 10, 16)
		if err != nil {
			return fmt.Errorf("parse link `%s` failed: invalid port: `%s`, error: %s", link, portStr, err)
		}
		if portUint64 == 0 || portUint64 > 0xffff {
			return fmt.Errorf("parse link `%s` failed: invalid port: `%s`", link, portStr)
		}
		port = uint16(portUint64)
	} else {
		if u.Scheme == "https" {
			port = 443
		} else {
			port = 80
		}
	}
	username := u.User.Username()
	password, _ := u.User.Password()
	options := &option.Outbound{
		Type: C.TypeHTTP,
		HTTPOptions: option.HTTPOutboundOptions{
			ServerOptions: option.ServerOptions{
				Server:     u.Hostname(),
				ServerPort: port,
			},
			Username: username,
			Password: password,
			Path:     u.Path,
		},
	}
	if u.Scheme == "https" {
		options.HTTPOptions.TLS = &option.OutboundTLSOptions{
			Enabled:    true,
			ServerName: u.Hostname(),
		}
	}
	if u.Fragment != "" {
		options.Tag = u.Fragment
	} else {
		options.Tag = net.JoinHostPort(options.HTTPOptions.Server, strconv.Itoa(int(options.HTTPOptions.ServerPort)))
	}
	p.options = options
	return nil
}

func (p *HTTP) Options() *option.Outbound {
	return p.options
}
