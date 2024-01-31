package outboundprovider

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
)

var _ action = (*actionDialer)(nil)

func init() {
	registerAction("setdialer", func() action {
		return &actionDialer{}
	})
}

type actionDialerOptions struct {
	Rules   option.Listable[string] `json:"rules,omitempty"`
	Logical string                  `json:"logical,omitempty"`
	Invert  bool                    `json:"invert,omitempty"`
	Dialer  map[string]any          `json:"dialer"`
}

type actionDialer struct {
	outboundMatcherGroup adapter.OutboundMatcher
	invert               bool
	dialer               map[string]any
}

func (a *actionDialer) UnmarshalJSON(content []byte) error {
	var options actionDialerOptions
	err := json.Unmarshal(content, &options)
	if err != nil {
		return err
	}
	logical := options.Logical
	if logical == "" {
		logical = "and"
	}
	a.outboundMatcherGroup, err = adapter.NewOutboundMatcherGroup(options.Rules, logical)
	if err != nil {
		return err
	}
	a.invert = options.Invert
	if options.Dialer == nil || len(options.Dialer) == 0 {
		return E.New("invalid dialer")
	}
	a.dialer = options.Dialer
	return nil
}

func (a *actionDialer) apply(_ context.Context, _ adapter.Router, logger log.ContextLogger, processor *processor) error {
	var outbounds []*option.Outbound
	processor.ForeachOutbounds(func(outbound *option.Outbound) bool {
		if a.outboundMatcherGroup.MatchOptions(outbound) {
			if !a.invert {
				outbounds = append(outbounds, outbound)
			}
		} else {
			if a.invert {
				outbounds = append(outbounds, outbound)
			}
		}
		return true
	})
	if len(outbounds) == 0 {
		return E.New("no outbounds matched")
	}
	for _, out := range outbounds {
		dialerOptions := getOutboundDialer(out)
		if dialerOptions == nil {
			return E.New("outbound [", out.Tag, "]: failed to get dialer options")
		}
		m, err := structToMap(dialerOptions)
		if err != nil {
			return E.Cause(err, "outbound [", out.Tag, "]: failed to parse dialer options")
		}
		for k := range a.dialer {
			kk := strings.TrimPrefix(k, "del_")
			if kk != k {
				delete(m, kk)
				logger.Debug("outbound [", out.Tag, "]: delete dialer option [", kk, "]")
				continue
			}
			kk = strings.TrimPrefix(k, "set_")
			if kk != k {
				v := a.dialer[k]
				m[kk] = v
				logger.Debug("outbound [", out.Tag, "]: set dialer option [", kk, "] -> ", fmt.Sprintf("%s", v))
				continue
			}
		}
		newDialerOptions, err := mapToStruct[option.DialerOptions](m)
		if err != nil {
			return E.Cause(err, "outbound [", out.Tag, "]: failed to parse dialer options")
		}
		setOutboundDialer(out, &newDialerOptions)
	}
	return nil
}

func getOutboundDialer(outbound *option.Outbound) *option.DialerOptions {
	var dialerOptions *option.DialerOptions
	switch outbound.Type {
	case C.TypeDirect:
		dialerOptions = &outbound.DirectOptions.DialerOptions
	case C.TypeSOCKS:
		dialerOptions = &outbound.SocksOptions.DialerOptions
	case C.TypeHTTP:
		dialerOptions = &outbound.HTTPOptions.DialerOptions
	case C.TypeShadowsocks:
		dialerOptions = &outbound.ShadowsocksOptions.DialerOptions
	case C.TypeVMess:
		dialerOptions = &outbound.VMessOptions.DialerOptions
	case C.TypeTrojan:
		dialerOptions = &outbound.TrojanOptions.DialerOptions
	case C.TypeWireGuard:
		dialerOptions = &outbound.WireGuardOptions.DialerOptions
	case C.TypeHysteria:
		dialerOptions = &outbound.HysteriaOptions.DialerOptions
	case C.TypeTor:
		dialerOptions = &outbound.TorOptions.DialerOptions
	case C.TypeSSH:
		dialerOptions = &outbound.SSHOptions.DialerOptions
	case C.TypeShadowTLS:
		dialerOptions = &outbound.ShadowTLSOptions.DialerOptions
	case C.TypeShadowsocksR:
		dialerOptions = &outbound.ShadowsocksROptions.DialerOptions
	case C.TypeVLESS:
		dialerOptions = &outbound.VLESSOptions.DialerOptions
	case C.TypeTUIC:
		dialerOptions = &outbound.TUICOptions.DialerOptions
	case C.TypeHysteria2:
		dialerOptions = &outbound.Hysteria2Options.DialerOptions
	}
	return dialerOptions
}

func setOutboundDialer(outbound *option.Outbound, dialer *option.DialerOptions) {
	newDialer := *dialer
	if dialer.Inet4BindAddress != nil {
		newDialer.Inet4BindAddress = new(option.ListenAddress)
		*newDialer.Inet4BindAddress = *dialer.Inet4BindAddress
	}
	if dialer.Inet6BindAddress != nil {
		newDialer.Inet6BindAddress = new(option.ListenAddress)
		*newDialer.Inet6BindAddress = *dialer.Inet6BindAddress
	}
	if dialer.UDPFragment != nil {
		newDialer.UDPFragment = new(bool)
		*newDialer.UDPFragment = *dialer.UDPFragment
	}
	switch outbound.Type {
	case C.TypeDirect:
		outbound.DirectOptions.DialerOptions = newDialer
	case C.TypeSOCKS:
		outbound.SocksOptions.DialerOptions = newDialer
	case C.TypeHTTP:
		outbound.HTTPOptions.DialerOptions = newDialer
	case C.TypeShadowsocks:
		outbound.ShadowsocksOptions.DialerOptions = newDialer
	case C.TypeVMess:
		outbound.VMessOptions.DialerOptions = newDialer
	case C.TypeTrojan:
		outbound.TrojanOptions.DialerOptions = newDialer
	case C.TypeWireGuard:
		outbound.WireGuardOptions.DialerOptions = newDialer
	case C.TypeHysteria:
		outbound.HysteriaOptions.DialerOptions = newDialer
	case C.TypeTor:
		outbound.TorOptions.DialerOptions = newDialer
	case C.TypeSSH:
		outbound.SSHOptions.DialerOptions = newDialer
	case C.TypeShadowTLS:
		outbound.ShadowTLSOptions.DialerOptions = newDialer
	case C.TypeShadowsocksR:
		outbound.ShadowsocksROptions.DialerOptions = newDialer
	case C.TypeVLESS:
		outbound.VLESSOptions.DialerOptions = newDialer
	case C.TypeTUIC:
		outbound.TUICOptions.DialerOptions = newDialer
	case C.TypeHysteria2:
		outbound.Hysteria2Options.DialerOptions = newDialer
	}
}

func mapToStruct[T any](m map[string]any) (T, error) {
	content, err := json.Marshal(m)
	if err != nil {
		return common.DefaultValue[T](), err
	}
	var v T
	err = json.Unmarshal(content, &v)
	if err != nil {
		return common.DefaultValue[T](), err
	}
	return v, nil
}

func structToMap[T any](s *T) (map[string]any, error) {
	content, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	err = json.Unmarshal(content, &m)
	if err != nil {
		return nil, err
	}
	return m, nil
}
