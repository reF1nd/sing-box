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

type VLESS struct {
	options *option.Outbound
}

func (p *VLESS) Tag() string {
	return p.options.Tag
}

func (p *VLESS) ParseLink(link string) error {
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
	uuid := u.User.Username()
	if uuid == "" {
		return fmt.Errorf("parse link `%s` failed: uuid is empty", link)
	}
	options := &option.Outbound{
		Type: C.TypeVLESS,
		VLESSOptions: option.VLESSOutboundOptions{
			ServerOptions: option.ServerOptions{
				Server:     u.Hostname(),
				ServerPort: port,
			},
			UUID: uuid,
		},
	}
	args, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return fmt.Errorf("parse link `%s` failed: %w", link, err)
	}
	security := args.Get("security")
	switch security {
	case "tls", "xtls", "reality":
		options.VLESSOptions.TLS = &option.OutboundTLSOptions{
			Enabled:    true,
			ServerName: u.Hostname(),
		}
		sni := args.Get("sni")
		if sni != "" {
			options.VLESSOptions.TLS.ServerName = sni
		}
		alpn := args.Get("alpn")
		if alpn != "" {
			alpns := strings.Split(alpn, ",")
			if len(alpns) > 1 {
				options.VLESSOptions.TLS.ALPN = make(option.Listable[string], 0)
				for _, alpn := range alpns {
					if alpn != "" {
						options.VLESSOptions.TLS.ALPN = append(options.VLESSOptions.TLS.ALPN, alpn)
					}
				}
			} else {
				options.VLESSOptions.TLS.ALPN = option.Listable[string]{alpn}
			}
		}
		if security == "tls" || security == "reality" {
			// TODO
			flow := args.Get("flow")
			options.VLESSOptions.Flow = flow
		}
		if security == "reality" {
			publicKey := args.Get("pbk")
			if publicKey == "" {
				return fmt.Errorf("parse link `%s` failed: public_key is empty", link)
			}
			shortID := args.Get("sid")
			if shortID == "" {
				return fmt.Errorf("parse link `%s` failed: short_id is empty", link)
			}
			options.VLESSOptions.TLS.Reality = &option.OutboundRealityOptions{
				Enabled:   true,
				PublicKey: publicKey,
				ShortID:   shortID,
			}
		}
		fp := args.Get("fp")
		if fp != "" {
			options.VLESSOptions.TLS.UTLS = &option.OutboundUTLSOptions{
				Enabled:     true,
				Fingerprint: fp,
			}
		}
	default:
		// TODO: security == 'none' || '' ???
	}
	_type := args.Get("type")
	switch _type {
	case "kcp":
		return fmt.Errorf("parse link `%s` failed: kcp unsupported", link)
	case "quic":
		quicSecurity := args.Get("quicSecurity")
		if quicSecurity != "" && quicSecurity != "none" {
			return fmt.Errorf("parse link `%s` failed: quic security unsupported", link)
		}
		options.VLESSOptions.Transport = &option.V2RayTransportOptions{
			Type:        C.V2RayTransportTypeQUIC,
			QUICOptions: option.V2RayQUICOptions{},
		}
	case "grpc":
		serviceName := args.Get("serviceName")
		options.VLESSOptions.Transport = &option.V2RayTransportOptions{
			Type: C.V2RayTransportTypeGRPC,
			GRPCOptions: option.V2RayGRPCOptions{
				ServiceName: serviceName,
			},
		}
	case "http":
		fallthrough
	case "tcp":
		headerType := args.Get("headerType")
		if _type == "http" || headerType == "http" {
			host := args.Get("host")
			var hosts []string
			_hosts := strings.Split(host, ",")
			for _, _host := range _hosts {
				if _host != "" {
					hosts = append(hosts, _host)
				}
			}
			path := args.Get("path")
			options.VLESSOptions.Transport = &option.V2RayTransportOptions{
				Type: C.V2RayTransportTypeHTTP,
				HTTPOptions: option.V2RayHTTPOptions{
					Host: hosts,
					Path: path,
				},
			}
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
		options.VLESSOptions.Transport = &option.V2RayTransportOptions{
			Type: C.V2RayTransportTypeWebsocket,
			WebsocketOptions: option.V2RayWebsocketOptions{
				Path:         path,
				MaxEarlyData: earlyData,
			},
		}
		if earlyData > 0 {
			options.VLESSOptions.Transport.WebsocketOptions.EarlyDataHeaderName = "Sec-WebSocket-Protocol"
		}
		host := args.Get("host")
		if host != "" && options.VLESSOptions.TLS == nil {
			options.VLESSOptions.Transport.WebsocketOptions.Headers = option.HTTPHeader{
				"Host": option.Listable[string]{host},
			}
		}
	default:
		return fmt.Errorf("parse link `%s` failed: invalid type: %s", link, _type)
	}
	if u.Fragment != "" {
		options.Tag = u.Fragment
	} else {
		options.Tag = net.JoinHostPort(options.VLESSOptions.Server, strconv.Itoa(int(options.VLESSOptions.ServerPort)))
	}
	p.options = options
	return nil
}

func (p *VLESS) Options() *option.Outbound {
	return p.options
}
