package parser

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badoption"
)

func ParseSubscriptionLink(link string) (option.Outbound, error) {
	reg := regexp.MustCompile(`^(.*://)(.*?)([?@#].*)?$`)
	result := reg.FindStringSubmatch(link)
	if len(result) > 1 {
		result[2], _ = decodeBase64URLSafe(result[2])
		link = strings.Join(result[1:], "")
	} else {
		return option.Outbound{}, E.New("not a link")
	}

	scheme := result[1][:len(result[1])-3]
	switch scheme {
	case "ss":
		return parseShadowsocksLink(link)
	case "tuic":
		return parseTuicLinik(link)
	case "vmess":
		return parseVMessLinik(link, len(result[1]))
	case "vless":
		return parseVLESSLinik(link)
	case "trojan":
		return parseTrojanLinik(link)
	case "hysteria":
		return parseHysteriaLinik(link)
	case "hy2", "hysteria2":
		return parseHysteria2Linik(link)
	default:
		return option.Outbound{}, E.New("unsupported scheme: ", scheme)
	}
}

func stringToInt64(str string) int64 {
	value, _ := strconv.ParseInt(str, 10, 64)
	return value
}

func stringToUint16(str string) uint16 {
	port, _ := strconv.ParseUint(str, 10, 16)
	return uint16(port)
}

func stringToUint32(str string) uint32 {
	port, _ := strconv.ParseUint(str, 10, 32)
	return uint32(port)
}

func splitKeyValueWithEqual(content string) (string, string) {
	if !strings.Contains(content, "=") {
		return content, "1"
	}
	arr := strings.Split(content, "=")
	return arr[0], arr[1]
}

func shadowsocksPluginName(plugin string) string {
	if index := strings.Index(plugin, ";"); index != -1 {
		return plugin[:index]
	}
	return plugin
}

func shadowsocksPluginOptions(plugin string) string {
	if index := strings.Index(plugin, ";"); index != -1 {
		return plugin[index+1:]
	}
	return ""
}

func parseShadowsocksLink(link string) (option.Outbound, error) {
	linkURL, err := url.Parse(link)
	if err != nil {
		return option.Outbound{}, err
	}

	if linkURL.User == nil {
		return option.Outbound{}, E.New("missing user info")
	}

	var options option.ShadowsocksOutboundOptions
	options.ServerOptions.Server = linkURL.Hostname()
	options.ServerOptions.ServerPort = stringToUint16(linkURL.Port())
	if password, _ := linkURL.User.Password(); password != "" {
		options.Method = linkURL.User.Username()
		options.Password = password
	} else {
		userAndPassword, _ := decodeBase64URLSafe(linkURL.User.Username())
		userAndPasswordParts := strings.Split(userAndPassword, ":")
		if len(userAndPasswordParts) != 2 {
			return option.Outbound{}, E.New("bad user info")
		}
		options.Method = userAndPasswordParts[0]
		options.Password = userAndPasswordParts[1]
	}

	plugin := linkURL.Query().Get("plugin")
	options.Plugin = shadowsocksPluginName(plugin)
	options.PluginOptions = shadowsocksPluginOptions(plugin)

	outbound := option.Outbound{
		Type: C.TypeShadowsocks,
		Tag:  linkURL.Fragment,
	}
	outbound.Options = &options
	return outbound, nil
}

func parseTuicLinik(link string) (option.Outbound, error) {
	linkURL, err := url.Parse(link)
	if err != nil {
		return option.Outbound{}, err
	}
	var options option.TUICOutboundOptions
	TLSOptions := option.OutboundTLSOptions{
		Enabled: true,
		ECH:     &option.OutboundECHOptions{},
		UTLS:    &option.OutboundUTLSOptions{},
		Reality: &option.OutboundRealityOptions{},
	}
	options.UUID = linkURL.User.Username()
	options.Password, _ = linkURL.User.Password()
	options.ServerOptions.Server = linkURL.Hostname()
	TLSOptions.ServerName = linkURL.Hostname()
	options.ServerOptions.ServerPort = stringToUint16(linkURL.Port())
	for key, values := range linkURL.Query() {
		value := values[len(values)-1]
		switch key {
		case "congestion_control":
			if value != "cubic" {
				options.CongestionControl = value
			}
		case "udp_relay_mode":
			options.UDPRelayMode = value
		case "udp_over_stream":
			if value == "true" || value == "1" {
				options.UDPOverStream = true
			}
		case "zero_rtt_handshake", "reduce_rtt":
			if value == "true" || value == "1" {
				options.ZeroRTTHandshake = true
			}
		case "heartbeat_interval":
			options.Heartbeat = badoption.Duration(stringToInt64(value))
		case "sni":
			TLSOptions.ServerName = value
		case "insecure", "skip-cert-verify", "allow_insecure":
			if value == "1" || value == "true" {
				TLSOptions.Insecure = true
			}
		case "disable_sni":
			if value == "1" || value == "true" {
				TLSOptions.DisableSNI = true
			}
		case "tfo", "tcp-fast-open", "tcp_fast_open":
			if value == "1" || value == "true" {
				options.TCPFastOpen = true
			}
		case "alpn":
			TLSOptions.ALPN = strings.Split(value, ",")
		}
	}
	if options.UDPOverStream {
		options.UDPRelayMode = ""
	}
	outbound := option.Outbound{
		Type: C.TypeTUIC,
		Tag:  linkURL.Fragment,
	}
	options.TLS = &TLSOptions
	outbound.Options = &options
	return outbound, nil
}

func parseVMessLinik(link string, schemeIndex int) (option.Outbound, error) {
	var proxy map[string]string
	err := json.Unmarshal([]byte(link[schemeIndex:]), &proxy)
	if err != nil {
		proxy = make(map[string]string)
		linkURL, err := url.Parse(link)
		if err != nil {
			return option.Outbound{}, err
		}
		if linkURL.User == nil || linkURL.User.Username() == "" {
			return option.Outbound{}, E.New("missing uuid")
		}
		proxy["id"] = linkURL.User.Username()
		proxy["add"] = linkURL.Hostname()
		proxy["port"] = linkURL.Port()
		proxy["ps"] = linkURL.Fragment
		for key, values := range linkURL.Query() {
			value := values[len(values)-1]
			switch key {
			case "type":
				if value == "http" {
					proxy["net"] = "tcp"
					proxy["type"] = "http"
				}
			case "encryption":
				proxy["scy"] = value
			case "alterId":
				proxy["aid"] = value
			case "key", "alpn", "seed", "path", "host":
				proxy[key] = value
			default:
				proxy[key] = value
			}
		}
	}
	outbound := option.Outbound{
		Type: C.TypeVMess,
	}
	options := option.VMessOutboundOptions{}
	TLSOptions := option.OutboundTLSOptions{
		ECH:     &option.OutboundECHOptions{},
		UTLS:    &option.OutboundUTLSOptions{},
		Reality: &option.OutboundRealityOptions{},
	}
	for key, value := range proxy {
		switch key {
		case "ps":
			outbound.Tag = value
		case "add":
			options.Server = value
			TLSOptions.ServerName = value
		case "port":
			options.ServerPort = stringToUint16(value)
		case "id":
			options.UUID = value
		case "scy":
			options.Security = value
		case "aid":
			options.AlterId, _ = strconv.Atoi(value)
		case "packet_encoding":
			options.PacketEncoding = value
		case "xudp":
			if value == "1" || value == "true" {
				options.PacketEncoding = "xudp"
			}
		case "tls":
			if value == "1" || value == "true" || value == "tls" {
				TLSOptions.Enabled = true
			}
		case "insecure", "skip-cert-verify":
			if value == "1" || value == "true" {
				TLSOptions.Insecure = true
			}
		case "fp":
			TLSOptions.UTLS.Enabled = true
			TLSOptions.UTLS.Fingerprint = value
		case "net":
			Transport := option.V2RayTransportOptions{
				Type: "",
				WebsocketOptions: option.V2RayWebsocketOptions{
					Headers: map[string]badoption.Listable[string]{},
				},
				HTTPOptions: option.V2RayHTTPOptions{
					Host:    badoption.Listable[string]{},
					Headers: map[string]badoption.Listable[string]{},
				},
				GRPCOptions: option.V2RayGRPCOptions{},
			}
			switch value {
			case "ws":
				Transport.Type = C.V2RayTransportTypeWebsocket
				if host, exists := proxy["host"]; exists && host != "" {
					for _, headerStr := range strings.Split(fmt.Sprint("Host:", host), "\n") {
						key, valueRaw := splitKeyValueWithEqual(headerStr)
						value := []string{}
						for _, item := range strings.Split(valueRaw, ",") {
							value = append(value, item)
						}
						Transport.WebsocketOptions.Headers[key] = value
					}
				}
				if path, exists := proxy["path"]; exists && path != "" {
					reg := regexp.MustCompile(`^(.*?)(?:\?ed=(\d*))?$`)
					result := reg.FindStringSubmatch(path)
					Transport.WebsocketOptions.Path = result[1]
					if result[2] != "" {
						Transport.WebsocketOptions.EarlyDataHeaderName = "Sec-WebSocket-Protocol"
						Transport.WebsocketOptions.MaxEarlyData = stringToUint32(result[2])
					}
				}
			case "h2":
				Transport.Type = C.V2RayTransportTypeHTTP
				TLSOptions.Enabled = true
				if host, exists := proxy["host"]; exists && host != "" {
					Transport.HTTPOptions.Host = []string{host}
				}
				if path, exists := proxy["path"]; exists && path != "" {
					Transport.HTTPOptions.Path = path
				}
			case "tcp":
				if tType, exists := proxy["type"]; exists {
					if tType == "http" {
						Transport.Type = C.V2RayTransportTypeHTTP
						if method, exists := proxy["method"]; exists {
							Transport.HTTPOptions.Method = method
						}
						if host, exists := proxy["host"]; exists && host != "" {
							Transport.HTTPOptions.Host = []string{host}
						}
						if path, exists := proxy["path"]; exists && path != "" {
							Transport.HTTPOptions.Path = path
						}
						if headers, exists := proxy["headers"]; exists {
							for _, header := range strings.Split(headers, "\n") {
								reg := regexp.MustCompile(`^[ \t]*?(\S+?):[ \t]*?(\S+?)[ \t]*?$`)
								result := reg.FindStringSubmatch(header)
								key := result[1]
								value := []string{}
								for _, item := range strings.Split(result[2], ",") {
									value = append(value, item)
								}
								Transport.HTTPOptions.Headers[key] = value
							}
						}
					}
				}
			case "grpc":
				Transport.Type = C.V2RayTransportTypeGRPC
				if host, exists := proxy["host"]; exists && host != "" {
					Transport.GRPCOptions.ServiceName = host
				}
			}
			options.Transport = &Transport
		case "tfo", "tcp-fast-open", "tcp_fast_open":
			if value == "1" || value == "true" {
				options.TCPFastOpen = true
			}
		}
	}
	options.TLS = &TLSOptions
	outbound.Options = &options
	return outbound, nil
}

func parseVLESSLinik(link string) (option.Outbound, error) {
	linkURL, err := url.Parse(link)
	if err != nil {
		return option.Outbound{}, err
	}
	if linkURL.User == nil || linkURL.User.Username() == "" {
		return option.Outbound{}, E.New("missing uuid")
	}
	var options option.VLESSOutboundOptions
	TLSOptions := option.OutboundTLSOptions{
		ECH:     &option.OutboundECHOptions{},
		UTLS:    &option.OutboundUTLSOptions{},
		Reality: &option.OutboundRealityOptions{},
	}
	options.UUID = linkURL.User.Username()
	options.Server = linkURL.Hostname()
	TLSOptions.ServerName = linkURL.Hostname()
	options.ServerPort = stringToUint16(linkURL.Port())
	proxy := map[string]string{}
	for key, values := range linkURL.Query() {
		value := values[len(values)-1]
		switch key {
		case "key", "alpn", "seed", "path", "host":
			proxy[key] = value
		default:
			proxy[key] = value
		}
	}
	for key, value := range proxy {
		switch key {
		case "type":
			Transport := option.V2RayTransportOptions{
				Type: "",
				WebsocketOptions: option.V2RayWebsocketOptions{
					Headers: map[string]badoption.Listable[string]{},
				},
				HTTPOptions: option.V2RayHTTPOptions{
					Host:    badoption.Listable[string]{},
					Headers: map[string]badoption.Listable[string]{},
				},
				GRPCOptions: option.V2RayGRPCOptions{},
			}
			switch value {
			case "kcp":
				return option.Outbound{}, E.New("unsupported transport type: kcp")
			case "ws":
				Transport.Type = C.V2RayTransportTypeWebsocket
				if host, exists := proxy["host"]; exists && host != "" {
					for _, header := range strings.Split(fmt.Sprint("Host:", host), "\n") {
						reg := regexp.MustCompile(`^[ \t]*?(\S+?):[ \t]*?(\S+?)[ \t]*?$`)
						result := reg.FindStringSubmatch(header)
						key := result[1]
						value := []string{}
						for _, item := range strings.Split(result[2], ",") {
							value = append(value, item)
						}
						Transport.WebsocketOptions.Headers[key] = value
					}
				}
				if path, exists := proxy["path"]; exists && path != "" {
					reg := regexp.MustCompile(`^(.*?)(?:\?ed=(\d*))?$`)
					result := reg.FindStringSubmatch(path)
					Transport.WebsocketOptions.Path = result[1]
					if result[2] != "" {
						Transport.WebsocketOptions.EarlyDataHeaderName = "Sec-WebSocket-Protocol"
						Transport.WebsocketOptions.MaxEarlyData = stringToUint32(result[2])
					}
				}
			case "http":
				Transport.Type = C.V2RayTransportTypeHTTP
				if host, exists := proxy["host"]; exists && host != "" {
					Transport.HTTPOptions.Host = strings.Split(host, ",")
				}
				if path, exists := proxy["path"]; exists && path != "" {
					Transport.HTTPOptions.Path = path
				}
			case "grpc":
				Transport.Type = C.V2RayTransportTypeGRPC
				if serviceName, exists := proxy["serviceName"]; exists && serviceName != "" {
					Transport.GRPCOptions.ServiceName = serviceName
				}
			}
			options.Transport = &Transport
		case "security":
			if value == "tls" {
				TLSOptions.Enabled = true
			} else if value == "reality" {
				TLSOptions.Enabled = true
				TLSOptions.Reality.Enabled = true
			}
		case "insecure", "skip-cert-verify":
			if value == "1" || value == "true" {
				TLSOptions.Insecure = true
			}
		case "serviceName", "sni", "peer":
			TLSOptions.ServerName = value
		case "alpn":
			TLSOptions.ALPN = strings.Split(value, ",")
		case "fp":
			TLSOptions.UTLS.Enabled = true
			TLSOptions.UTLS.Fingerprint = value
		case "flow":
			if value == "xtls-rprx-vision" {
				options.Flow = "xtls-rprx-vision"
			}
		case "pbk":
			TLSOptions.Reality.PublicKey = value
		case "sid":
			TLSOptions.Reality.ShortID = value
		case "tfo", "tcp-fast-open", "tcp_fast_open":
			if value == "1" || value == "true" {
				options.TCPFastOpen = true
			}
		}
	}
	outbound := option.Outbound{
		Type: C.TypeVLESS,
		Tag:  linkURL.Fragment,
	}
	options.TLS = &TLSOptions
	outbound.Options = &options
	return outbound, nil
}

func parseTrojanLinik(link string) (option.Outbound, error) {
	linkURL, err := url.Parse(link)
	if err != nil {
		return option.Outbound{}, err
	}
	if linkURL.User == nil || linkURL.User.Username() == "" {
		return option.Outbound{}, E.New("missing password")
	}
	var options option.TrojanOutboundOptions
	TLSOptions := option.OutboundTLSOptions{
		Enabled: true,
		ECH:     &option.OutboundECHOptions{},
		UTLS:    &option.OutboundUTLSOptions{},
		Reality: &option.OutboundRealityOptions{},
	}
	options.Server = linkURL.Hostname()
	TLSOptions.ServerName = linkURL.Hostname()
	options.ServerPort = stringToUint16(linkURL.Port())
	options.Password = linkURL.User.Username()
	proxy := map[string]string{}
	for key, values := range linkURL.Query() {
		value := values[len(values)-1]
		proxy[key] = value
	}
	for key, value := range proxy {
		switch key {
		case "insecure", "allowInsecure", "skip-cert-verify":
			if value == "1" || value == "true" {
				TLSOptions.Insecure = true
			}
		case "serviceName", "sni", "peer":
			TLSOptions.ServerName = value
		case "alpn":
			TLSOptions.ALPN = strings.Split(value, ",")
		case "fp":
			TLSOptions.UTLS.Enabled = true
			TLSOptions.UTLS.Fingerprint = value
		case "type":
			Transport := option.V2RayTransportOptions{
				Type: "",
				WebsocketOptions: option.V2RayWebsocketOptions{
					Headers: map[string]badoption.Listable[string]{},
				},
				HTTPOptions: option.V2RayHTTPOptions{
					Host:    badoption.Listable[string]{},
					Headers: map[string]badoption.Listable[string]{},
				},
				GRPCOptions: option.V2RayGRPCOptions{},
			}
			switch value {
			case "ws":
				Transport.Type = C.V2RayTransportTypeWebsocket
				if host, exists := proxy["host"]; exists && host != "" {
					for _, header := range strings.Split(fmt.Sprint("Host:", host), "\n") {
						reg := regexp.MustCompile(`^[ \t]*?(\S+?):[ \t]*?(\S+?)[ \t]*?$`)
						result := reg.FindStringSubmatch(header)
						key := result[1]
						value := []string{}
						for _, item := range strings.Split(result[2], ",") {
							value = append(value, item)
						}
						Transport.WebsocketOptions.Headers[key] = value
					}
				}
				if path, exists := proxy["path"]; exists && path != "" {
					reg := regexp.MustCompile(`^(.*?)(?:\?ed=(\d*))?$`)
					result := reg.FindStringSubmatch(path)
					Transport.WebsocketOptions.Path = result[1]
					if result[2] != "" {
						Transport.WebsocketOptions.EarlyDataHeaderName = "Sec-WebSocket-Protocol"
						Transport.WebsocketOptions.MaxEarlyData = stringToUint32(result[2])
					}
				}
			case "grpc":
				Transport.Type = C.V2RayTransportTypeGRPC
				if serviceName, exists := proxy["grpc-service-name"]; exists && serviceName != "" {
					Transport.GRPCOptions.ServiceName = serviceName
				}
			}
			options.Transport = &Transport
		case "tfo", "tcp-fast-open", "tcp_fast_open":
			if value == "1" || value == "true" {
				options.TCPFastOpen = true
			}
		}
	}
	outbound := option.Outbound{
		Type: C.TypeTrojan,
		Tag:  linkURL.Fragment,
	}
	options.TLS = &TLSOptions
	outbound.Options = &options
	return outbound, nil
}

func parseHysteriaLinik(link string) (option.Outbound, error) {
	linkURL, err := url.Parse(link)
	if err != nil {
		return option.Outbound{}, err
	}
	var options option.HysteriaOutboundOptions
	TLSOptions := option.OutboundTLSOptions{
		Enabled: true,
		ECH:     &option.OutboundECHOptions{},
		UTLS:    &option.OutboundUTLSOptions{},
		Reality: &option.OutboundRealityOptions{},
	}
	options.Server = linkURL.Hostname()
	TLSOptions.ServerName = linkURL.Hostname()
	options.ServerPort = stringToUint16(linkURL.Port())
	for key, values := range linkURL.Query() {
		value := values[len(values)-1]
		switch key {
		case "auth":
			options.AuthString = value
		case "peer", "sni":
			TLSOptions.ServerName = value
		case "alpn":
			TLSOptions.ALPN = strings.Split(value, ",")
		case "ca":
			TLSOptions.CertificatePath = value
		case "ca_str":
			TLSOptions.Certificate = strings.Split(value, "\n")
		case "up":
			options.Up = value
		case "up_mbps":
			options.UpMbps, _ = strconv.Atoi(value)
		case "down":
			options.Down = value
		case "down_mbps":
			options.DownMbps, _ = strconv.Atoi(value)
		case "obfs", "obfsParam":
			options.Obfs = value
		case "insecure", "skip-cert-verify":
			if value == "1" || value == "true" {
				TLSOptions.Insecure = true
			}
		case "tfo", "tcp-fast-open", "tcp_fast_open":
			if value == "1" || value == "true" {
				options.TCPFastOpen = true
			}
		}
	}
	outbound := option.Outbound{
		Type: C.TypeHysteria,
		Tag:  linkURL.Fragment,
	}
	options.TLS = &TLSOptions
	outbound.Options = &options
	return outbound, nil
}

func parseHysteria2Linik(link string) (option.Outbound, error) {
	linkURL, err := url.Parse(link)
	if err != nil {
		return option.Outbound{}, err
	}
	var options option.Hysteria2OutboundOptions
	TLSOptions := option.OutboundTLSOptions{
		Enabled: true,
		ECH:     &option.OutboundECHOptions{},
		UTLS:    &option.OutboundUTLSOptions{},
		Reality: &option.OutboundRealityOptions{},
	}
	options.ServerPort = uint16(443)
	options.Server = linkURL.Hostname()
	TLSOptions.ServerName = linkURL.Hostname()
	if password, _ := linkURL.User.Password(); password != "" {
		options.Password = password
	} else {
		options.Password = linkURL.User.Username()
	}
	if linkURL.Port() != "" {
		options.ServerPort = stringToUint16(linkURL.Port())
	}
	for key, values := range linkURL.Query() {
		value := values[len(values)-1]
		switch key {
		case "up":
			options.UpMbps, _ = strconv.Atoi(value)
		case "down":
			options.DownMbps, _ = strconv.Atoi(value)
		case "obfs":
			if value == "salamander" {
				options.Obfs.Type = "salamander"
			}
		case "obfs-password":
			options.Obfs.Password = value
		case "insecure", "skip-cert-verify":
			if value == "1" || value == "true" {
				TLSOptions.Insecure = true
			}
		}
	}
	outbound := option.Outbound{
		Type: C.TypeHysteria2,
		Tag:  linkURL.Fragment,
	}
	options.TLS = &TLSOptions
	outbound.Options = &options
	return outbound, nil
}
