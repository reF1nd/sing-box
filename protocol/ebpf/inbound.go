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
	ebpfModeLocal        = "local"
	ebpfModeShared       = "shared"
	ebpfModeHybrid       = "hybrid"
	dnsModeHijack        = "hijack"
	dnsModeRespectPolicy = "respect_policy"
	dnsModeOff           = "off"
)

var (
	redirectIPv4Candidates = []netip.Prefix{
		netip.MustParsePrefix("127.128.0.0/9"),
		netip.MustParsePrefix("127.64.0.0/10"),
	}
	redirectIPv6Candidates = []netip.Prefix{
		netip.MustParsePrefix("fd53:696e:672d:626f::/64"),
		netip.MustParsePrefix("fd53:696e:672d:6270::/64"),
	}
)

type fakeIPRangeProvider interface {
	FakeIPRanges() (netip.Prefix, netip.Prefix)
}

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.EBPFInboundOptions](registry, C.TypeEBPF, NewInbound)
}

type Inbound struct {
	inbound.Adapter
	ctx                          context.Context
	router                       adapter.ConnectionRouterEx
	logger                       log.ContextLogger
	networkManager               adapter.NetworkManager
	cgroupEnabled                bool
	cgroupPath                   string
	listeners                    internalListenerSet
	udpNat                       *udpnat.Service
	cgroupBackend                *ECommon.CgroupBackend
	socketProtector              *socketProtector
	socketProtectionRegistration *adapter.EBPFSocketProtectionRegistration
	udpTimeout                   time.Duration
	enableTCP                    bool
	enableUDP                    bool
	localDNSMode                 string
	sharedDNSMode                string
	localIPv6                    bool
	redirectIPv4Prefix           netip.Prefix
	redirectIPv6Prefix           netip.Prefix
	cgroupMapCapacity            ECommon.CgroupMapCapacity
	cgroupPolicy                 ECommon.CgroupPolicy
	androidUIDOptions            *androidUIDOptions
	localRoutes                  []*localRoute
	sharedNetworkOptions         option.EBPFSharedOptions
	sharedNetworkEnabled         bool
	sharedIPv6                   bool
	sharedNetworkMapCapacity     ECommon.SharedNetworkMapCapacities
	localBypassPrivateAddress    bool
	sharedBypassPrivateAddress   bool
	fakeIPIPv4Prefix             netip.Prefix
	fakeIPIPv6Prefix             netip.Prefix
	sharedNetworkIncludeMAC      []ECommon.MACAddress
	sharedNetworkExcludeMAC      []ECommon.MACAddress
	sharedNetwork                *sharedNetwork
	cgroupBackendAccess          sync.RWMutex
	lifecycleAccess              sync.Mutex

	bypassRuleSetAccess    sync.Mutex
	bypassRuleSet          []adapter.RuleSet
	bypassRuleSetPolicy    ECommon.BypassCIDRPolicy
	bypassRuleSetDirty     bool
	bypassRuleSetCallbacks []*list.Element[adapter.RuleSetUpdateCallback]
	bypassRuleSetStarted   bool

	udpClientTable    udpClientTable
	udpWarnings       udpWarningLimiters
	tcpWarnings       warningLimiter
	policyWarnings    warningLimiter
	tcpJanitorWarn    warningLimiter
	maintenanceAccess sync.RWMutex
	tcpJanitorStop    context.CancelFunc
	tcpJanitorDone    chan struct{}
	tcpJanitorWake    chan struct{}
	debug             eBPFDebugState
}

var _ adapter.InterfaceUpdateListener = (*Inbound)(nil)

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.EBPFInboundOptions) (adapter.Inbound, error) {
	_, cgroupEnabled, sharedNetworkEnabled, err := normalizeMode(options.Mode)
	if err != nil {
		return nil, err
	}
	if err = validateLocalOptions(cgroupEnabled, options.Local); err != nil {
		return nil, err
	}
	if err = validateSharedOptions(sharedNetworkEnabled, options.Shared); err != nil {
		return nil, err
	}
	if err = validateAndroidUIDOptions(runtime.GOOS, options.Local); err != nil {
		return nil, err
	}
	cgroupPath, err := normalizeCgroupPath(options.Local.CgroupPath)
	if err != nil {
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
	sharedNetworkOptions := option.EBPFSharedOptions{}
	if sharedNetworkEnabled {
		sharedNetworkOptions, err = normalizeSharedNetworkOptions(options.Shared)
		if err != nil {
			return nil, err
		}
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
	network := options.Network.Build()
	enableTCP := common.Contains(network, N.NetworkTCP)
	enableUDP := common.Contains(network, N.NetworkUDP)
	networkManager := service.FromContext[adapter.NetworkManager](ctx)
	if networkManager == nil {
		return nil, E.New("missing network manager")
	}
	inbound := &Inbound{
		Adapter:                    inbound.NewAdapter(C.TypeEBPF, tag),
		ctx:                        ctx,
		router:                     router,
		logger:                     logger,
		networkManager:             networkManager,
		cgroupEnabled:              cgroupEnabled,
		cgroupPath:                 cgroupPath,
		enableTCP:                  enableTCP,
		enableUDP:                  enableUDP,
		localDNSMode:               localDNSMode,
		sharedDNSMode:              sharedDNSMode,
		localIPv6:                  cgroupEnabled && enabledByDefault(options.Local.IPv6),
		redirectIPv4Prefix:         redirectIPv4Candidates[0],
		redirectIPv6Prefix:         redirectIPv6Candidates[0],
		cgroupMapCapacity:          ECommon.DefaultCgroupMapCapacity(),
		sharedNetworkOptions:       sharedNetworkOptions,
		sharedNetworkEnabled:       sharedNetworkEnabled,
		sharedIPv6:                 sharedNetworkEnabled && enabledByDefault(options.Shared.IPv6),
		sharedNetworkMapCapacity:   ECommon.DefaultSharedNetworkMapCapacities(),
		localBypassPrivateAddress:  options.Local.BypassPrivateAddress == nil || *options.Local.BypassPrivateAddress,
		sharedBypassPrivateAddress: options.Shared.BypassPrivateAddress == nil || *options.Shared.BypassPrivateAddress,
		sharedNetworkIncludeMAC:    sharedNetworkIncludeMAC,
		sharedNetworkExcludeMAC:    sharedNetworkExcludeMAC,
		cgroupPolicy: ECommon.CgroupPolicy{
			DNSMode:              commonDNSMode(localDNSMode),
			BypassPrivateAddress: options.Local.BypassPrivateAddress == nil || *options.Local.BypassPrivateAddress,
			IncludeUIDConfigured: len(options.Local.IncludeUID) > 0 ||
				len(options.Local.IncludeUIDRange) > 0 || len(options.Local.IncludePackage) > 0,
			IncludeUID: includeUIDRanges,
			ExcludeUID: excludeUIDRanges,
		},
		androidUIDOptions: newAndroidUIDOptions(options.Local),
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
	if cgroupEnabled {
		inbound.socketProtector = newSocketProtector()
	}
	return inbound, nil
}

func commonDNSMode(mode string) ECommon.DNSMode {
	switch mode {
	case dnsModeRespectPolicy:
		return ECommon.DNSModeRespectPolicy
	case dnsModeOff:
		return ECommon.DNSModeOff
	default:
		return ECommon.DNSModeHijack
	}
}
