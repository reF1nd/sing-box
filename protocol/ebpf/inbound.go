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
	commonEBPF "github.com/sagernet/sing-box/common/ebpf"
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
	ebpfModeLocal        = "local"
	ebpfModeShared       = "shared"
	ebpfModeHybrid       = "hybrid"
	dnsModeHijack        = "hijack"
	dnsModeRespectPolicy = "respect_policy"
	dnsModeOff           = "off"
	defaultTCPriority    = 1
)

type fakeIPRangeProvider interface {
	FakeIPRanges() (netip.Prefix, netip.Prefix)
}

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.EBPFInboundOptions](registry, C.TypeEBPF, NewInbound)
}

type Inbound struct {
	inbound.Adapter
	ctx                      context.Context
	router                   adapter.Router
	logger                   log.ContextLogger
	networkManager           adapter.NetworkManager
	mode                     string
	localEnabled             bool
	selfBypass               *commonEBPF.SelfBypass
	selfBypassCgroup         bool
	processTracker           *commonEBPF.ProcessTracker
	usePlatformProcessFinder bool
	listeners                internalListenerSet
	udpNat                   *udpnat.Service
	tcDataPlane              *tcDataPlane
	udpTimeout               time.Duration
	enableTCP                bool
	enableUDP                bool
	localDNSMode             string
	sharedDNSMode            string
	localIPv6                bool
	localPolicy              commonEBPF.LocalPolicy
	androidUIDOptions        *androidUIDOptions
	sharedOptions            option.EBPFSharedOptions
	sharedEnabled            bool
	sharedIPv6               bool
	sharedBypassPrivate      bool
	localBypassPort          []commonEBPF.PortRange
	sharedBypassPort         []commonEBPF.PortRange
	tcPriority               uint16
	fakeIPIPv4Prefix         netip.Prefix
	fakeIPIPv6Prefix         netip.Prefix
	sharedIncludeMAC         []commonEBPF.MACAddress
	sharedExcludeMAC         []commonEBPF.MACAddress
	tcDataPlaneAccess        sync.RWMutex
	lifecycleAccess          sync.Mutex
	interfaceMonitor         tcInterfaceMonitor

	bypassRuleSetAccess    sync.Mutex
	bypassRuleSet          []adapter.RuleSet
	bypassRuleSetCallbacks []*list.Element[adapter.RuleSetUpdateCallback]
	bypassRuleSetStarted   bool

	udpClientTable    udpClientTable
	udpReplySockets   udpReplySocketPool
	udpWarnings       udpWarningLimiters
	tcpWarnings       warningLimiter
	policyWarnings    warningLimiter
	interfaceWarnings interfaceWarningLimiters
}

var _ adapter.InterfaceUpdateListener = (*Inbound)(nil)

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.EBPFInboundOptions) (adapter.Inbound, error) {
	mode, localEnabled, sharedEnabled, err := normalizeMode(options.Mode)
	if err != nil {
		return nil, err
	}
	if err = validateLocalOptions(localEnabled, options.Local); err != nil {
		return nil, err
	}
	if err = validateSharedOptions(sharedEnabled, options.Shared); err != nil {
		return nil, err
	}
	if err = validateAndroidUIDOptions(runtime.GOOS, options.Local); err != nil {
		return nil, err
	}
	localDNSMode, err := normalizeDNSMode(options.Local.DNSMode)
	if err != nil {
		return nil, E.Cause(err, "parse local.dns_mode")
	}
	sharedDNSMode, err := normalizeDNSMode(options.Shared.DNSMode)
	if err != nil {
		return nil, E.Cause(err, "parse shared.dns_mode")
	}
	includeUIDRanges, err := parseUIDRanges(options.Local.IncludeUID, options.Local.IncludeUIDRange)
	if err != nil {
		return nil, E.Cause(err, "parse include_uid_range")
	}
	excludeUIDRanges, err := parseUIDRanges(options.Local.ExcludeUID, options.Local.ExcludeUIDRange)
	if err != nil {
		return nil, E.Cause(err, "parse exclude_uid_range")
	}
	sharedOptions := option.EBPFSharedOptions{}
	if sharedEnabled {
		sharedOptions, err = normalizeSharedOptions(options.Shared)
		if err != nil {
			return nil, err
		}
	}
	localBypassPort, err := parsePortRanges("local.bypass_port", options.Local.BypassPort, options.Local.BypassPortRange)
	if err != nil {
		return nil, err
	}
	sharedBypassPort, err := parsePortRanges("shared.bypass_port", options.Shared.BypassPort, options.Shared.BypassPortRange)
	if err != nil {
		return nil, err
	}
	sharedIncludeMAC, err := parseSharedMACAddresses(
		"include_mac_address",
		sharedOptions.IncludeMACAddress,
	)
	if err != nil {
		return nil, err
	}
	sharedExcludeMAC, err := parseSharedMACAddresses(
		"exclude_mac_address",
		sharedOptions.ExcludeMACAddress,
	)
	if err != nil {
		return nil, err
	}
	network := options.Network.Build()
	enableTCP := common.Contains(network, N.NetworkTCP)
	enableUDP := common.Contains(network, N.NetworkUDP)
	networkManager := service.FromContext[adapter.NetworkManager](ctx)
	if networkManager == nil {
		return nil, E.New("missing network manager")
	}
	var selfBypass *commonEBPF.SelfBypass
	if localEnabled {
		provider, loaded := networkManager.(interface {
			EBPFSelfBypass() *commonEBPF.SelfBypass
		})
		if loaded {
			selfBypass = provider.EBPFSelfBypass()
		}
		if selfBypass == nil {
			return nil, E.New("eBPF self-bypass sockets were not prepared")
		}
	}
	inbound := &Inbound{
		Adapter:        inbound.NewAdapter(C.TypeEBPF, tag),
		ctx:            ctx,
		router:         router,
		logger:         logger,
		networkManager: networkManager,
		usePlatformProcessFinder: func() bool {
			platform := service.FromContext[adapter.PlatformInterface](ctx)
			return platform != nil && platform.UsePlatformConnectionOwnerFinder()
		}(),
		mode:                mode,
		localEnabled:        localEnabled,
		selfBypass:          selfBypass,
		enableTCP:           enableTCP,
		enableUDP:           enableUDP,
		localDNSMode:        localDNSMode,
		sharedDNSMode:       sharedDNSMode,
		localIPv6:           localEnabled && enabledByDefault(options.Local.IPv6),
		sharedOptions:       sharedOptions,
		sharedEnabled:       sharedEnabled,
		sharedIPv6:          sharedEnabled && enabledByDefault(options.Shared.IPv6),
		sharedBypassPrivate: options.Shared.BypassPrivateAddress == nil || *options.Shared.BypassPrivateAddress,
		localBypassPort:     localBypassPort,
		sharedBypassPort:    sharedBypassPort,
		tcPriority:          uint16(options.TCPriority),
		sharedIncludeMAC:    sharedIncludeMAC,
		sharedExcludeMAC:    sharedExcludeMAC,
		localPolicy: commonEBPF.LocalPolicy{
			DNSMode:              toCommonDNSMode(localDNSMode),
			BypassPrivateAddress: options.Local.BypassPrivateAddress == nil || *options.Local.BypassPrivateAddress,
			IncludeUIDConfigured: len(options.Local.IncludeUID) > 0 ||
				len(options.Local.IncludeUIDRange) > 0 || len(options.Local.IncludePackage) > 0,
			IncludeUID: includeUIDRanges,
			ExcludeUID: excludeUIDRanges,
		},
		androidUIDOptions: newAndroidUIDOptions(options.Local),
	}
	if inbound.tcPriority == 0 {
		inbound.tcPriority = defaultTCPriority
	}
	if dnsTransportManager := service.FromContext[adapter.DNSTransportManager](ctx); dnsTransportManager != nil {
		if fakeIPTransport := dnsTransportManager.FakeIP(); fakeIPTransport != nil {
			if rangeProvider, loaded := fakeIPTransport.Store().(fakeIPRangeProvider); loaded {
				inbound.fakeIPIPv4Prefix, inbound.fakeIPIPv6Prefix = rangeProvider.FakeIPRanges()
			}
		}
	}
	if err = inbound.normalizeFakeIPPrefixes(); err != nil {
		return nil, err
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

func toCommonDNSMode(mode string) commonEBPF.DNSMode {
	switch mode {
	case dnsModeRespectPolicy:
		return commonEBPF.DNSModeRespectPolicy
	case dnsModeOff:
		return commonEBPF.DNSModeOff
	default:
		return commonEBPF.DNSModeHijack
	}
}
