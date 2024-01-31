package raw

import (
	"fmt"
	"net"
	"net/url"
	"strconv"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

type Hysteria struct {
	options *option.Outbound
}

func (p *Hysteria) Tag() string {
	return p.options.Tag
}

func (p *Hysteria) ParseLink(link string) error {
	u, err := url.Parse(link)
	if err != nil {
		return fmt.Errorf("parse link `%s` failed: %w", link, err)
	}
	portStr := u.Port()
	if portStr == "" {
		return fmt.Errorf("parse link `%s` failed: port is empty", link)
	}
	portUint64, err := strconv.ParseUint(u.Port(), 10, 16)
	if err != nil {
		return fmt.Errorf("parse link `%s` failed: invalid port: `%s`, error: %s", link, portStr, err)
	}
	port := uint16(portUint64)
	args, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return fmt.Errorf("parse link `%s` failed: parse args failed: %w", link, err)
	}
	protocol := args.Get("protocol")
	switch protocol {
	case "udp", "":
	case "wechat-video", "faketcp":
		return fmt.Errorf("parse link `%s` failed: protocol `%s` is not supported", link, protocol)
	default:
		return fmt.Errorf("parse link `%s` failed: invalid protocol: %s", link, protocol)
	}
	auth := args.Get("auth")
	sni := args.Get("peer")
	var insecure bool
	insecureStr := args.Get("insecure")
	switch insecureStr {
	case "1", "true":
		insecure = true
	}
	upmbpsStr := args.Get("upmbps")
	upmbps, err := strconv.ParseUint(upmbpsStr, 10, 64)
	if err != nil {
		return fmt.Errorf("parse link `%s` failed: invalid upmbps `%s`", link, upmbpsStr)
	}
	downmbpsStr := args.Get("downmbps")
	downmbps, err := strconv.ParseUint(downmbpsStr, 10, 64)
	if err != nil {
		return fmt.Errorf("parse link `%s` failed: invalid downmbps `%s`", link, downmbpsStr)
	}
	alpn := args.Get("alpn")
	// TODO: How to do ??
	obfs := args.Get("obfs")
	if obfs == "" {
		obfs = "xplus"
	}
	//
	obfsParam := args.Get("obfsParam")
	options := &option.Outbound{
		Type: C.TypeHysteria,
		HysteriaOptions: option.HysteriaOutboundOptions{
			ServerOptions: option.ServerOptions{
				Server:     u.Hostname(),
				ServerPort: port,
			},
			AuthString: auth,
			UpMbps:     int(upmbps),
			DownMbps:   int(downmbps),
			Obfs:       obfsParam,
			OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
				TLS: &option.OutboundTLSOptions{
					Enabled:    true,
					Insecure:   insecure,
					ServerName: sni,
				},
			},
		},
	}
	if options.HysteriaOptions.TLS.ServerName == "" {
		options.HysteriaOptions.TLS.ServerName = options.HysteriaOptions.Server
	}
	if alpn != "" {
		options.HysteriaOptions.TLS.ALPN = []string{alpn}
	}
	if u.Fragment != "" {
		options.Tag = u.Fragment
	} else {
		options.Tag = net.JoinHostPort(options.HysteriaOptions.Server, strconv.Itoa(int(options.HysteriaOptions.ServerPort)))
	}
	p.options = options
	return nil
}

func (p *Hysteria) Options() *option.Outbound {
	return p.options
}
