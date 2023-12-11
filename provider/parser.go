package provider

import (
	"reflect"
	"strings"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-dns"
	E "github.com/sagernet/sing/common/exceptions"
)

func newParser(content string, dialerOptions *option.OverrideDialerOptions) ([]option.Outbound, error) {
	var outbounds []option.Outbound
	var err error
	switch true {
	case strings.Contains(content, "\"outbounds\""):
		var options option.OutboundProviderOptions
		err = options.UnmarshalJSON([]byte(content))
		if err != nil {
			return nil, E.Cause(err, "decode config at ")
		}
		outbounds = options.Outbounds
	case strings.Contains(content, "proxies"):
		outbounds, err = newClashParser(content)
		if err != nil {
			return nil, err
		}
	default:
		outbounds, err = newNativeURIParser(content)
		if err != nil {
			return nil, err
		}
	}
	return overrideOutbounds(outbounds, dialerOptions), nil
}

func overrideOutbounds(outbounds []option.Outbound, dialerOptions *option.OverrideDialerOptions) []option.Outbound {
	var testOpt option.OverrideDialerOptions
	if dialerOptions == nil || reflect.DeepEqual(*dialerOptions, testOpt) {
		return outbounds
	}
	parsedOutbounds := []option.Outbound{}
	for _, outbound := range outbounds {
		switch outbound.Type {
		case C.TypeHTTP:
			dialer := outbound.HTTPOptions.DialerOptions
			outbound.HTTPOptions.DialerOptions = overrideDialerOption(dialer, dialerOptions)
		case C.TypeSOCKS:
			dialer := outbound.SocksOptions.DialerOptions
			outbound.SocksOptions.DialerOptions = overrideDialerOption(dialer, dialerOptions)
		case C.TypeTUIC:
			dialer := outbound.TUICOptions.DialerOptions
			outbound.TUICOptions.DialerOptions = overrideDialerOption(dialer, dialerOptions)
		case C.TypeVMess:
			dialer := outbound.VMessOptions.DialerOptions
			outbound.VMessOptions.DialerOptions = overrideDialerOption(dialer, dialerOptions)
		case C.TypeVLESS:
			dialer := outbound.VLESSOptions.DialerOptions
			outbound.VLESSOptions.DialerOptions = overrideDialerOption(dialer, dialerOptions)
		case C.TypeTrojan:
			dialer := outbound.TrojanOptions.DialerOptions
			outbound.TrojanOptions.DialerOptions = overrideDialerOption(dialer, dialerOptions)
		case C.TypeHysteria:
			dialer := outbound.HysteriaOptions.DialerOptions
			outbound.HysteriaOptions.DialerOptions = overrideDialerOption(dialer, dialerOptions)
		case C.TypeShadowTLS:
			dialer := outbound.ShadowTLSOptions.DialerOptions
			outbound.ShadowTLSOptions.DialerOptions = overrideDialerOption(dialer, dialerOptions)
		case C.TypeHysteria2:
			dialer := outbound.Hysteria2Options.DialerOptions
			outbound.Hysteria2Options.DialerOptions = overrideDialerOption(dialer, dialerOptions)
		case C.TypeWireGuard:
			dialer := outbound.WireGuardOptions.DialerOptions
			outbound.WireGuardOptions.DialerOptions = overrideDialerOption(dialer, dialerOptions)
		case C.TypeShadowsocks:
			dialer := outbound.ShadowsocksOptions.DialerOptions
			outbound.ShadowsocksOptions.DialerOptions = overrideDialerOption(dialer, dialerOptions)
		case C.TypeShadowsocksR:
			dialer := outbound.ShadowsocksROptions.DialerOptions
			outbound.ShadowsocksROptions.DialerOptions = overrideDialerOption(dialer, dialerOptions)
		}
		parsedOutbounds = append(parsedOutbounds, outbound)
	}
	return parsedOutbounds
}

func overrideDialerOption(options option.DialerOptions, dialerOptions *option.OverrideDialerOptions) option.DialerOptions {
	force := dialerOptions.ForceOverride
	if dialerOptions.Detour != nil && (options.Detour != "" || !force) {
		options.Detour = *dialerOptions.Detour
	}
	if dialerOptions.BindInterface != nil && (options.BindInterface == "" || force) {
		options.BindInterface = *dialerOptions.BindInterface
	}
	if dialerOptions.Inet4BindAddress != nil && (options.Inet4BindAddress == nil || force) {
		options.Inet4BindAddress = dialerOptions.Inet4BindAddress
	}
	if dialerOptions.Inet6BindAddress != nil && (options.Inet6BindAddress == nil || force) {
		options.Inet6BindAddress = dialerOptions.Inet6BindAddress
	}
	if dialerOptions.ProtectPath != nil && (options.ProtectPath == "" || force) {
		options.ProtectPath = *dialerOptions.ProtectPath
	}
	if dialerOptions.RoutingMark != nil && (options.RoutingMark == 0 || force) {
		options.RoutingMark = *dialerOptions.RoutingMark
	}
	if dialerOptions.ReuseAddr != nil && (!options.ReuseAddr || force) {
		options.ReuseAddr = *dialerOptions.ReuseAddr
	}
	if dialerOptions.ConnectTimeout != nil && (options.ConnectTimeout != option.Duration(0) || force) {
		options.ConnectTimeout = *dialerOptions.ConnectTimeout
	}
	if dialerOptions.TCPFastOpen != nil && (!options.TCPFastOpen || force) {
		options.TCPFastOpen = *dialerOptions.TCPFastOpen
	}
	if dialerOptions.TCPMultiPath != nil && (!options.TCPMultiPath || force) {
		options.TCPMultiPath = *dialerOptions.TCPMultiPath
	}
	if dialerOptions.UDPFragment != nil && (options.UDPFragment != nil || force) {
		options.UDPFragment = dialerOptions.UDPFragment
	}
	if dialerOptions.DomainStrategy != nil && (options.DomainStrategy != option.DomainStrategy(dns.DomainStrategyAsIS) || force) {
		options.DomainStrategy = *dialerOptions.DomainStrategy
	}
	if dialerOptions.FallbackDelay != nil && (options.FallbackDelay != option.Duration(0) || force) {
		options.FallbackDelay = *dialerOptions.FallbackDelay
	}
	if dialerOptions.ResolveUDP != nil && (!options.ResolveUDP || force) {
		options.ResolveUDP = *dialerOptions.ResolveUDP
	}
	return options
}
