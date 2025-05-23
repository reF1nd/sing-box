package parser

import (
	"context"
	"reflect"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
)

var subscriptionParsers = []func(ctx context.Context, content string) ([]option.Outbound, []option.Endpoint, error){
	ParseBoxSubscription,
	ParseClashSubscription,
	ParseSIP008Subscription,
	ParseRawSubscription,
}

func ParseSubscription(ctx context.Context, content string, overrideDialerOptions *option.OverrideDialerOptions, providerTag string) ([]option.Outbound, []option.Endpoint, error) {
	var pErr error
	for _, parser := range subscriptionParsers {
		outbounds, endpoints, err := parser(ctx, content)
		if len(outbounds) > 0 || len(endpoints) > 0 {
			return overrideOutbounds(outbounds, overrideDialerOptions, providerTag),
				overrideEndpoints(endpoints, overrideDialerOptions, providerTag),
				nil
		}
		pErr = E.Errors(pErr, err)
	}
	return nil, nil, E.Cause(pErr, "no servers found")
}

func overrideOutbounds(outbounds []option.Outbound, overrideDialerOptions *option.OverrideDialerOptions, providerTag string) []option.Outbound {
	var tags []string
	for _, outbound := range outbounds {
		tags = append(tags, outbound.Tag)
	}
	var parsedOutbounds []option.Outbound
	for _, outbound := range outbounds {
		switch outbound.Type {
		case C.TypeHTTP:
			options := outbound.Options.(*option.HTTPOutboundOptions)
			options.DialerOptions = overrideDialerOption(options.DialerOptions, overrideDialerOptions, tags, providerTag)
			outbound.Options = options
		case C.TypeSOCKS:
			options := outbound.Options.(*option.SOCKSOutboundOptions)
			options.DialerOptions = overrideDialerOption(options.DialerOptions, overrideDialerOptions, tags, providerTag)
			outbound.Options = options
		case C.TypeTUIC:
			options := outbound.Options.(*option.TUICOutboundOptions)
			options.DialerOptions = overrideDialerOption(options.DialerOptions, overrideDialerOptions, tags, providerTag)
			outbound.Options = options
		case C.TypeVMess:
			options := outbound.Options.(*option.VMessOutboundOptions)
			options.DialerOptions = overrideDialerOption(options.DialerOptions, overrideDialerOptions, tags, providerTag)
			outbound.Options = options
		case C.TypeVLESS:
			options := outbound.Options.(*option.VLESSOutboundOptions)
			options.DialerOptions = overrideDialerOption(options.DialerOptions, overrideDialerOptions, tags, providerTag)
			outbound.Options = options
		case C.TypeTrojan:
			options := outbound.Options.(*option.TrojanOutboundOptions)
			options.DialerOptions = overrideDialerOption(options.DialerOptions, overrideDialerOptions, tags, providerTag)
			outbound.Options = options
		case C.TypeHysteria:
			options := outbound.Options.(*option.HysteriaOutboundOptions)
			options.DialerOptions = overrideDialerOption(options.DialerOptions, overrideDialerOptions, tags, providerTag)
			outbound.Options = options
		case C.TypeShadowTLS:
			options := outbound.Options.(*option.ShadowTLSOutboundOptions)
			options.DialerOptions = overrideDialerOption(options.DialerOptions, overrideDialerOptions, tags, providerTag)
			outbound.Options = options
		case C.TypeHysteria2:
			options := outbound.Options.(*option.Hysteria2OutboundOptions)
			options.DialerOptions = overrideDialerOption(options.DialerOptions, overrideDialerOptions, tags, providerTag)
			outbound.Options = options
		case C.TypeAnyTLS:
			options := outbound.Options.(*option.AnyTLSOutboundOptions)
			options.DialerOptions = overrideDialerOption(options.DialerOptions, overrideDialerOptions, tags, providerTag)
			outbound.Options = options
		case C.TypeShadowsocks:
			options := outbound.Options.(*option.ShadowsocksOutboundOptions)
			options.DialerOptions = overrideDialerOption(options.DialerOptions, overrideDialerOptions, tags, providerTag)
			outbound.Options = options
		}
		parsedOutbounds = append(parsedOutbounds, outbound)
	}
	return parsedOutbounds
}

func overrideEndpoints(endpoints []option.Endpoint, overrideDialerOptions *option.OverrideDialerOptions, providerTag string) []option.Endpoint {
	if len(endpoints) == 0 {
		return nil
	}
	var tags []string
	for _, ep := range endpoints {
		tags = append(tags, ep.Tag)
	}
	var parsedEndpoints []option.Endpoint
	for _, ep := range endpoints {
		switch ep.Type {
		case C.TypeWireGuard:
			options := ep.Options.(*option.WireGuardEndpointOptions)
			options.DialerOptions = overrideDialerOption(options.DialerOptions, overrideDialerOptions, tags, providerTag)
			ep.Options = options
		}
		parsedEndpoints = append(parsedEndpoints, ep)
	}
	return parsedEndpoints
}

func overrideDialerOption(options option.DialerOptions, overrideDialerOptions *option.OverrideDialerOptions, tags []string, providerTag string) option.DialerOptions {
	if options.Detour != "" {
		if common.Any(tags, func(tag string) bool {
			return options.Detour == tag
		}) {
			if providerTag != "" {
				options.Detour = providerTag + "/" + options.Detour
			}
		} else {
			options.Detour = ""
		}
	}
	var defaultOptions option.OverrideDialerOptions
	if overrideDialerOptions == nil || reflect.DeepEqual(*overrideDialerOptions, defaultOptions) {
		return options
	}
	if overrideDialerOptions.Detour != nil && options.Detour == "" {
		options.Detour = *overrideDialerOptions.Detour
	}
	if overrideDialerOptions.BindInterface != nil {
		options.BindInterface = *overrideDialerOptions.BindInterface
	}
	if overrideDialerOptions.Inet4BindAddress != nil {
		options.Inet4BindAddress = overrideDialerOptions.Inet4BindAddress
	}
	if overrideDialerOptions.Inet6BindAddress != nil {
		options.Inet6BindAddress = overrideDialerOptions.Inet6BindAddress
	}
	if overrideDialerOptions.ProtectPath != nil {
		options.ProtectPath = *overrideDialerOptions.ProtectPath
	}
	if overrideDialerOptions.RoutingMark != nil {
		options.RoutingMark = *overrideDialerOptions.RoutingMark
	}
	if overrideDialerOptions.ReuseAddr != nil {
		options.ReuseAddr = *overrideDialerOptions.ReuseAddr
	}
	if overrideDialerOptions.ConnectTimeout != nil {
		options.ConnectTimeout = *overrideDialerOptions.ConnectTimeout
	}
	if overrideDialerOptions.TCPFastOpen != nil {
		options.TCPFastOpen = *overrideDialerOptions.TCPFastOpen
	}
	if overrideDialerOptions.TCPMultiPath != nil {
		options.TCPMultiPath = *overrideDialerOptions.TCPMultiPath
	}
	if overrideDialerOptions.UDPFragment != nil {
		options.UDPFragment = overrideDialerOptions.UDPFragment
	}
	options.DomainResolver = overrideDialerOptions.DomainResolver
	if overrideDialerOptions.NetworkStrategy != nil {
		options.NetworkStrategy = overrideDialerOptions.NetworkStrategy
	}
	if overrideDialerOptions.NetworkType != nil {
		options.NetworkType = *overrideDialerOptions.NetworkType
	}
	if overrideDialerOptions.FallbackNetworkType != nil {
		options.FallbackNetworkType = *overrideDialerOptions.FallbackNetworkType
	}
	if overrideDialerOptions.FallbackDelay != nil {
		options.FallbackDelay = *overrideDialerOptions.FallbackDelay
	}
	if overrideDialerOptions.TCPKeepAlive != nil {
		options.TCPKeepAlive = *overrideDialerOptions.TCPKeepAlive
	}
	if overrideDialerOptions.TCPKeepAliveInterval != nil {
		options.TCPKeepAliveInterval = *overrideDialerOptions.TCPKeepAliveInterval
	}
	if overrideDialerOptions.TCPKeepAliveCount != nil {
		options.TCPKeepAliveCount = *overrideDialerOptions.TCPKeepAliveCount
	}
	if overrideDialerOptions.DisableTCPKeepAlive != nil {
		options.DisableTCPKeepAlive = *overrideDialerOptions.DisableTCPKeepAlive
	}

	//nolint:staticcheck
	if overrideDialerOptions.DomainStrategy != nil {
		options.DomainStrategy = *overrideDialerOptions.DomainStrategy
	}
	return options
}
