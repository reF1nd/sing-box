package raw

import (
	"fmt"
	"net"
	"net/url"
	"strconv"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

type Hysteria2 struct {
	options *option.Outbound
}

func (p *Hysteria2) Tag() string {
	return p.options.Tag
}

func (p *Hysteria2) ParseLink(link string) error {
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
		port = 443
	}
	args, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return fmt.Errorf("parse link `%s` failed: parse args failed: %w", link, err)
	}
	sni := args.Get("sni")
	if sni == "" {
		sni = args.Get("peer")
	}
	var insecure bool
	insecureStr := args.Get("insecure")
	switch insecureStr {
	case "1", "true":
		insecure = true
	}
	obfs := args.Get("obfs")
	obfsPassword := args.Get("obfs-password")
	// TODO: pinSHA256 ????
	options := &option.Outbound{
		Type: C.TypeHysteria2,
		Hysteria2Options: option.Hysteria2OutboundOptions{
			ServerOptions: option.ServerOptions{
				Server:     u.Hostname(),
				ServerPort: port,
			},
			Password: u.User.Username(),
			OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
				TLS: &option.OutboundTLSOptions{
					Enabled:    true,
					Insecure:   insecure,
					ServerName: sni,
				},
			},
		},
	}
	if obfs != "" && obfsPassword != "" {
		options.Hysteria2Options.Obfs = &option.Hysteria2Obfs{
			Type:     obfs,
			Password: obfsPassword,
		}
	}
	if options.Hysteria2Options.TLS.ServerName == "" {
		options.Hysteria2Options.TLS.ServerName = options.Hysteria2Options.Server
	}
	if u.Fragment != "" {
		options.Tag = u.Fragment
	} else {
		options.Tag = net.JoinHostPort(options.Hysteria2Options.Server, strconv.Itoa(int(options.Hysteria2Options.ServerPort)))
	}
	p.options = options
	return nil
}

func (p *Hysteria2) Options() *option.Outbound {
	return p.options
}
