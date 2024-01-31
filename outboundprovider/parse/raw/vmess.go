package raw

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

type VMess struct {
	options *option.Outbound
}

func (p *VMess) Tag() string {
	return p.options.Tag
}

func (p *VMess) ParseLink(link string) error {
	sLink := strings.TrimPrefix(link, "vmess://")
	raw, err := base64.URLEncoding.DecodeString(sLink)
	if err != nil {
		return fmt.Errorf("parse link `%s` failed: %w", link, err)
	}
	var _vmessInfo vmessInfo
	err = json.Unmarshal(raw, &_vmessInfo)
	if err != nil {
		return fmt.Errorf("parse link `%s` failed: %w", link, err)
	}
	//
	if _vmessInfo.Version != "2" {
		return fmt.Errorf("parse link `%s` failed: invalid version: `%s`", link, _vmessInfo.Version)
	}
	portUint64, err := strconv.ParseUint(_vmessInfo.Port, 10, 16)
	if err != nil {
		return fmt.Errorf("parse link `%s` failed: invalid port: `%s`, error: %s", link, _vmessInfo.Port, err)
	}
	port := uint16(portUint64)
	aidInt64, err := strconv.ParseInt(_vmessInfo.AID, 10, 64)
	if err != nil {
		return fmt.Errorf("parse link `%s` failed: invalid alterId: `%s`, error: %s", link, _vmessInfo.AID, err)
	}
	options := &option.Outbound{
		Type: C.TypeVMess,
		VMessOptions: option.VMessOutboundOptions{
			ServerOptions: option.ServerOptions{
				Server:     _vmessInfo.Address,
				ServerPort: port,
			},
			UUID:    _vmessInfo.ID,
			AlterId: int(aidInt64),
		},
	}
	if _vmessInfo.Security != "" {
		options.VMessOptions.Security = _vmessInfo.Security
	} else {
		options.VMessOptions.Security = "auto"
	}
	if _vmessInfo.TLS == "tls" {
		options.VMessOptions.TLS = &option.OutboundTLSOptions{
			Enabled: true,
		}
		if _vmessInfo.SNI != "" {
			options.VMessOptions.TLS.ServerName = _vmessInfo.SNI
		} else if _vmessInfo.Host != "" {
			options.VMessOptions.TLS.ServerName = _vmessInfo.Host
		} else {
			options.VMessOptions.TLS.ServerName = _vmessInfo.Address
		}
		if _vmessInfo.ALPN != "" {
			alpns := strings.Split(_vmessInfo.ALPN, ",")
			if len(alpns) > 1 {
				options.VLESSOptions.TLS.ALPN = make(option.Listable[string], 0)
				for _, alpn := range alpns {
					if alpn != "" {
						options.VLESSOptions.TLS.ALPN = append(options.VLESSOptions.TLS.ALPN, alpn)
					}
				}
			} else {
				options.VLESSOptions.TLS.ALPN = option.Listable[string]{_vmessInfo.ALPN}
			}
		}
	}
	switch _vmessInfo.Network {
	case "kcp":
		return fmt.Errorf("parse link `%s` failed: kcp unsupported", link)
	case "quic":
		quicSecurity := _vmessInfo.Type
		if quicSecurity != "" && quicSecurity != "none" {
			return fmt.Errorf("parse link `%s` failed: quic security unsupported", link)
		}
		options.VLESSOptions.Transport = &option.V2RayTransportOptions{
			Type:        C.V2RayTransportTypeQUIC,
			QUICOptions: option.V2RayQUICOptions{},
		}
	case "grpc":
		options.VMessOptions.Transport = &option.V2RayTransportOptions{
			Type: C.V2RayTransportTypeGRPC,
			GRPCOptions: option.V2RayGRPCOptions{
				ServiceName: _vmessInfo.Path,
			},
		}
	case "h2":
		fallthrough
	case "tcp":
		if _vmessInfo.Network == "h2" || _vmessInfo.Type == "http" {
			host := _vmessInfo.Host
			var hosts []string
			_hosts := strings.Split(host, ",")
			for _, _host := range _hosts {
				if _host != "" {
					hosts = append(hosts, _host)
				}
			}
			options.VMessOptions.Transport = &option.V2RayTransportOptions{
				Type: C.V2RayTransportTypeHTTP,
				HTTPOptions: option.V2RayHTTPOptions{
					Host: hosts,
					Path: _vmessInfo.Path,
				},
			}
		}
	case "ws":
		path := _vmessInfo.Path
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
		options.VMessOptions.Transport = &option.V2RayTransportOptions{
			Type: C.V2RayTransportTypeWebsocket,
			WebsocketOptions: option.V2RayWebsocketOptions{
				Path:         path,
				MaxEarlyData: earlyData,
			},
		}
		if earlyData > 0 {
			options.VMessOptions.Transport.WebsocketOptions.EarlyDataHeaderName = "Sec-WebSocket-Protocol"
		}
		host := _vmessInfo.Host
		if host != "" && options.VMessOptions.TLS == nil {
			options.VMessOptions.Transport.WebsocketOptions.Headers = option.HTTPHeader{
				"Host": option.Listable[string]{host},
			}
		}
	default:
		return fmt.Errorf("parse link `%s` failed: invalid type: %s", link, _vmessInfo.Network)
	}
	if _vmessInfo.Tag != "" {
		options.Tag = _vmessInfo.Tag
	} else {
		options.Tag = net.JoinHostPort(options.VMessOptions.Server, strconv.Itoa(int(options.VMessOptions.ServerPort)))
	}
	p.options = options
	return nil
}

func (p *VMess) Options() *option.Outbound {
	return p.options
}

type vmessInfo struct {
	Version     string `json:"v"`
	Tag         string `json:"ps"`
	Address     string `json:"add"`
	Port        string `json:"port"`
	ID          string `json:"id"`
	AID         string `json:"aid"`
	Security    string `json:"scy"`
	Network     string `json:"net"`
	Type        string `json:"type"`
	Host        string `json:"host"`
	Path        string `json:"path"`
	TLS         string `json:"tls"`
	SNI         string `json:"sni"`
	ALPN        string `json:"alpn"`
	Fingerprint string `json:"fingerprint"`
}
