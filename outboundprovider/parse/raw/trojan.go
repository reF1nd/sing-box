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

type Trojan struct {
	options *option.Outbound
}

func (p *Trojan) Tag() string {
	return p.options.Tag
}

func (p *Trojan) ParseLink(link string) error {
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
	password := u.User.Username()
	if password == "" {
		return fmt.Errorf("parse link `%s` failed: password is empty", link)
	}
	options := &option.Outbound{
		Type: C.TypeTrojan,
		TrojanOptions: option.TrojanOutboundOptions{
			ServerOptions: option.ServerOptions{
				Server:     u.Hostname(),
				ServerPort: port,
			},
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
		sni := args.Get("sni")
		if sni != "" {
			options.TrojanOptions.TLS.ServerName = sni
		}
		_type := args.Get("type")
		switch _type {
		case "tcp", "":
		case "grpc":
			serviceName := args.Get("serviceName")
			options.TrojanOptions.Transport = &option.V2RayTransportOptions{
				Type: C.V2RayTransportTypeGRPC,
				GRPCOptions: option.V2RayGRPCOptions{
					ServiceName: serviceName,
				},
			}
		case "ws":
			path := args.Get("path")
			var earlyData uint32
			paths := strings.Split(path, "?ed=")
			if len(paths) == 2 {
				earlyDataUint64, err := strconv.ParseUint(paths[1], 10, 32)
				if err != nil {
					return fmt.Errorf("parse link `%s` failed: invalid path `%s`", link, path)
				}
				earlyData = uint32(earlyDataUint64)
				path = paths[0]
			}
			options.TrojanOptions.Transport = &option.V2RayTransportOptions{
				Type: C.V2RayTransportTypeWebsocket,
				WebsocketOptions: option.V2RayWebsocketOptions{
					Path:         path,
					MaxEarlyData: earlyData,
				},
			}
			if earlyData > 0 {
				options.TrojanOptions.Transport.WebsocketOptions.EarlyDataHeaderName = "Sec-WebSocket-Protocol"
			}
		default:
			return fmt.Errorf("parse link `%s` failed: invalid type: %s", link, _type)
		}
	}
	if u.Fragment != "" {
		options.Tag = u.Fragment
	} else {
		options.Tag = net.JoinHostPort(options.TrojanOptions.Server, strconv.Itoa(int(options.TrojanOptions.ServerPort)))
	}
	p.options = options
	return nil
}

func (p *Trojan) Options() *option.Outbound {
	return p.options
}
