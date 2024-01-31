package raw

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

type Socks struct {
	options *option.Outbound
}

func (p *Socks) Tag() string {
	return p.options.Tag
}

func (p *Socks) ParseLink(link string) error {
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
		port = 1080
	}
	username := u.User.Username()
	password, _ := u.User.Password()
	options := &option.Outbound{
		Type: C.TypeSOCKS,
		SocksOptions: option.SocksOutboundOptions{
			ServerOptions: option.ServerOptions{
				Server:     u.Hostname(),
				ServerPort: port,
			},
			Username: username,
			Password: password,
		},
	}
	if strings.Contains(u.Scheme, "4") {
		options.SocksOptions.Version = "4"
	} else if strings.Contains(u.Scheme, "4a") {
		options.SocksOptions.Version = "4a"
	} else {
		options.SocksOptions.Version = "5"
	}
	if u.Fragment != "" {
		options.Tag = u.Fragment
	} else {
		options.Tag = net.JoinHostPort(options.SocksOptions.Server, strconv.Itoa(int(options.SocksOptions.ServerPort)))
	}
	p.options = options
	return nil
}

func (p *Socks) Options() *option.Outbound {
	return p.options
}
