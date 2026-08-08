//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"net/netip"
	"runtime"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	ECommon "github.com/sagernet/sing-box/common/ebpf"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"
	udpnat "github.com/sagernet/sing/common/udpnat2"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service"
)

const (
	androidTetheringDNSUID = 1052
	dnsModeHijack          = "hijack"
	dnsModeOff             = "off"
	cgroupIPv6ModeAlways   = "always"
	cgroupIPv6ModeAuto     = "auto"
	cgroupIPv6ModeOff      = "off"
)

var defaultRedirectIPv4Prefix = netip.MustParsePrefix("127.128.0.0/9")

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.EBPFInboundOptions](registry, C.TypeEBPF, NewInbound)
}

type Inbound struct {
	inbound.Adapter
	ctx                      context.Context
	router                   adapter.ConnectionRouterEx
	logger                   log.ContextLogger
	networkManager           adapter.NetworkManager
	cgroupEnabled            bool
	cgroupPath               string
	listeners                internalListenerSet
	udpNat                   *udpnat.Service
	cgroupBackend            *ECommon.CgroupBackend
	protectRegistered        bool
	udpTimeout               time.Duration
	enableTCP                bool
	enableUDP                bool
	dnsMode                  string
	cgroupIPv6Mode           string
	cgroupIPv6Available      bool
	cgroupIPv6Probe          cgroupIPv6ProbeState
	redirectIPv4Prefix       netip.Prefix
	redirectIPv6Prefix       netip.Prefix
	cgroupMapCapacity        ECommon.CgroupMapCapacity
	cgroupPolicy             ECommon.CgroupPolicy
	androidUIDOptions        *androidUIDOptions
	localRoutes              []*localRoute
	sharedNetworkOptions     option.EBPFSharedNetworkOptions
	sharedNetworkMapCapacity ECommon.SharedNetworkMapCapacities
	bypassPrivateAddress     bool
	sharedNetworkIncludeMAC  []ECommon.MACAddress
	sharedNetworkExcludeMAC  []ECommon.MACAddress
	sharedNetwork            *sharedNetwork
	cgroupBackendAccess      sync.RWMutex
	lifecycleAccess          sync.Mutex

	bypassRuleSetAccess    sync.Mutex
	bypassRuleSet          []adapter.RuleSet
	bypassCIDR             []netip.Prefix
	bypassRuleSetCallbacks []*list.Element[adapter.RuleSetUpdateCallback]
	bypassRuleSetStarted   bool

	udpClientTable udpClientTable
	udpWarnings    udpWarningLimiters
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.EBPFInboundOptions) (adapter.Inbound, error) {
	cgroupEnabled := options.CgroupEnabled == nil || *options.CgroupEnabled
	if err := validateCgroupOptions(cgroupEnabled, options); err != nil {
		return nil, err
	}
	if err := validateAndroidUIDOptions(runtime.GOOS, options); err != nil {
		return nil, err
	}
	cgroupPath, err := normalizeCgroupPath(options.CgroupPath)
	if err != nil {
		return nil, err
	}
	redirectIPv4Prefix, redirectIPv6Prefix, err := normalizeRedirectAddresses(options.RedirectAddress)
	if err != nil {
		return nil, err
	}
	dnsMode, err := normalizeDNSMode(options.DNSMode)
	if err != nil {
		return nil, err
	}
	cgroupIPv6Mode, err := normalizeCgroupIPv6Mode(options.CgroupIPv6Mode)
	if err != nil {
		return nil, err
	}
	if err = validateCgroupAddressFamilies(
		cgroupEnabled,
		cgroupIPv6Mode,
		redirectIPv4Prefix,
		redirectIPv6Prefix,
	); err != nil {
		return nil, err
	}
	cgroupMapCapacity, err := normalizeCgroupMapCapacity(options.MapCapacity)
	if err != nil {
		return nil, err
	}
	includeUIDRanges, err := parseUIDRanges(options.IncludeUID, options.IncludeUIDRange)
	if err != nil {
		return nil, E.Cause(err, "parse include_uid_range")
	}
	excludeUIDRanges, err := parseUIDRanges(options.ExcludeUID, options.ExcludeUIDRange)
	if err != nil {
		return nil, E.Cause(err, "parse exclude_uid_range")
	}
	excludeUIDRanges = append(excludeUIDRanges, platformExcludedUIDRanges(runtime.GOOS)...)
	sharedNetworkOptions, err := normalizeSharedNetworkOptions(options.SharedNetwork)
	if err != nil {
		return nil, err
	}
	if err = validateDataPaths(cgroupEnabled, sharedNetworkOptions.Enabled); err != nil {
		return nil, err
	}
	sharedNetworkIncludeMAC, err := parseSharedNetworkMACAddresses(
		"include_mac_address",
		sharedNetworkOptions.IncludeMACAddress,
	)
	if err != nil {
		return nil, err
	}
	sharedNetworkExcludeMAC, err := parseSharedNetworkMACAddresses(
		"exclude_mac_address",
		sharedNetworkOptions.ExcludeMACAddress,
	)
	if err != nil {
		return nil, err
	}
	sharedNetworkMapCapacity, err := normalizeSharedNetworkMapCapacity(sharedNetworkOptions.MapCapacity)
	if err != nil {
		return nil, err
	}
	network := options.Network.Build()
	enableTCP := common.Contains(network, N.NetworkTCP)
	enableUDP := common.Contains(network, N.NetworkUDP)
	if err = validateSharedNetworkProtocols(sharedNetworkOptions, enableUDP, dnsMode); err != nil {
		return nil, err
	}
	networkManager := service.FromContext[adapter.NetworkManager](ctx)
	if networkManager == nil {
		return nil, E.New("missing network manager")
	}
	inbound := &Inbound{
		Adapter:                  inbound.NewAdapter(C.TypeEBPF, tag),
		ctx:                      ctx,
		router:                   router,
		logger:                   logger,
		networkManager:           networkManager,
		cgroupEnabled:            cgroupEnabled,
		cgroupPath:               cgroupPath,
		enableTCP:                enableTCP,
		enableUDP:                enableUDP,
		dnsMode:                  dnsMode,
		cgroupIPv6Mode:           cgroupIPv6Mode,
		cgroupIPv6Available:      true,
		redirectIPv4Prefix:       redirectIPv4Prefix,
		redirectIPv6Prefix:       redirectIPv6Prefix,
		cgroupMapCapacity:        cgroupMapCapacity,
		sharedNetworkOptions:     sharedNetworkOptions,
		sharedNetworkMapCapacity: sharedNetworkMapCapacity,
		bypassPrivateAddress:     options.BypassPrivateAddress == nil || *options.BypassPrivateAddress,
		sharedNetworkIncludeMAC:  sharedNetworkIncludeMAC,
		sharedNetworkExcludeMAC:  sharedNetworkExcludeMAC,
		cgroupPolicy: ECommon.CgroupPolicy{
			HijackDNS: dnsMode == dnsModeHijack,
			IncludeUIDConfigured: len(options.IncludeUID) > 0 ||
				len(options.IncludeUIDRange) > 0 || len(options.IncludePackage) > 0,
			IncludeUID:              includeUIDRanges,
			ExcludeUID:              excludeUIDRanges,
			ExcludeAndroidDNSTether: runtime.GOOS == "android",
		},
		androidUIDOptions: newAndroidUIDOptions(options),
	}
	for _, ruleSetTag := range options.BypassRuleSet {
		ruleSet, loaded := router.RuleSet(ruleSetTag)
		if !loaded {
			return nil, E.New("parse bypass_rule_set: rule-set not found: ", ruleSetTag)
		}
		inbound.bypassRuleSet = append(inbound.bypassRuleSet, ruleSet)
	}
	udpTimeout := C.UDPTimeout
	if options.UDPTimeout != 0 {
		udpTimeout = time.Duration(options.UDPTimeout)
	}
	inbound.udpTimeout = udpTimeout
	inbound.udpNat = udpnat.New(inbound, inbound.preparePacketConnection, udpTimeout, false)
	return inbound, nil
}
