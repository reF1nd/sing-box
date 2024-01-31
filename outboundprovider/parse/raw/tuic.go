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

type Tuic struct {
	options *option.Outbound
}

func (p *Tuic) Tag() string {
	return p.options.Tag
}

func (p *Tuic) ParseLink(link string) error {
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
	uuid := u.User.Username()
	if uuid == "" {
		return fmt.Errorf("parse link `%s` failed: uuid is empty", link)
	}
	password, ok := u.User.Password()
	if !ok || password == "" {
		return fmt.Errorf("parse link `%s` failed: password is empty", link)
	}
	options := &option.Outbound{
		Type: C.TypeTUIC,
		TUICOptions: option.TUICOutboundOptions{
			ServerOptions: option.ServerOptions{
				Server:     u.Hostname(),
				ServerPort: port,
			},
			UUID:     uuid,
			Password: password,
			OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
				TLS: &option.OutboundTLSOptions{
					Enabled:    true,
					ServerName: u.Hostname(),
				},
			},
		},
	}
	args, err := url.ParseQuery(u.RawQuery)
	if err == nil {
		congestionControl := args.Get("congestion_control")
		udpRelayMode := args.Get("udp_relay_mode")
		options.TUICOptions.CongestionControl = congestionControl
		options.TUICOptions.UDPRelayMode = udpRelayMode

		sni := args.Get("sni")
		if sni != "" {
			options.TUICOptions.TLS.ServerName = sni
		}
		alpn := args.Get("alpn")
		if alpn != "" {
			alpns := strings.Split(alpn, ",")
			if len(alpns) > 1 {
				options.TUICOptions.TLS.ALPN = make(option.Listable[string], 0)
				for _, alpn := range alpns {
					if alpn != "" {
						options.TUICOptions.TLS.ALPN = append(options.TUICOptions.TLS.ALPN, alpn)
					}
				}
			} else {
				options.TUICOptions.TLS.ALPN = option.Listable[string]{alpn}
			}
		}
	}
	if u.Fragment != "" {
		options.Tag = u.Fragment
	} else {
		options.Tag = net.JoinHostPort(options.TUICOptions.Server, strconv.Itoa(int(options.TUICOptions.ServerPort)))
	}
	p.options = options
	return nil
}

func (p *Tuic) Options() *option.Outbound {
	return p.options
}
