//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	commonEBPF "github.com/CHIZI-0618/sing-ebpf"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

const (
	sharedDataPlaneSocketAssign  = "socket_assign"
	sharedDataPlanePacketRewrite = "packet_rewrite"
	dnsModeHijack                = "hijack"
	dnsModeRespectPolicy         = "respect_policy"
	dnsModeOff                   = "off"
	defaultTCPriority            = 1
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

type processTrackerOwner interface {
	LookupOwner(socketCookie uint64) (commonEBPF.ProcessSocketOwner, error)
	ReleaseCleanup() bool
	IsClosed() bool
	Close() error
}

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.EBPFInboundOptions](registry, C.TypeEBPF, NewInbound)
}

type Inbound struct {
	inbound.Adapter
	ctx                       context.Context
	router                    adapter.Router
	logger                    log.ContextLogger
	networkManager            adapter.NetworkManager
	localEnabled              bool
	localDataPlane            string
	cgroupPath                string
	cgroupBackend             *commonEBPF.CgroupBackend
	localRoutes               *commonEBPF.LocalRouteSet
	redirectIPv4Prefix        netip.Prefix
	redirectIPv6Prefix        netip.Prefix
	selfBypass                *commonEBPF.SelfBypass
	selfBypassCgroup          bool
	processTracker            processTrackerOwner
	processTrackerRollback    processTrackerOwner
	processInfoCache          *processInfoCache
	usePlatformProcessFinder  bool
	listeners                 internalListenerSet
	tcListeners               internalListenerSet
	tcNamespace               *tcNamespace
	tcNamespaceAccess         sync.RWMutex
	udpNat                    *udpNATService
	tcDataPlane               tcRuntime
	udpTimeout                time.Duration
	udpFragment               bool
	enableTCP                 bool
	enableUDP                 bool
	localDNSMode              string
	sharedDNSMode             string
	localIPv6                 bool
	localPolicy               localUIDPolicy
	compiledPolicy            commonEBPF.CompiledPolicy
	androidUIDOptions         *androidUIDOptions
	sharedOptions             option.EBPFSharedOptions
	sharedEnabled             bool
	sharedDataPlane           string
	sharedRewrite             *sharedRewrite
	sharedRewriteAccess       sync.RWMutex
	sharedIPv6                bool
	sharedBypassPrivate       bool
	localBypassPort           []portRange
	sharedBypassPort          []portRange
	localBypassExclude        []netip.Prefix
	sharedBypassExclude       []netip.Prefix
	tcPriority                uint16
	networkGeneration         uint64
	fakeIPIPv4Prefix          netip.Prefix
	fakeIPIPv6Prefix          netip.Prefix
	fakeIPICMPReply           bool
	sharedIncludeMAC          []commonEBPF.MACAddress
	sharedExcludeMAC          []commonEBPF.MACAddress
	localInitialDestinations  []commonEBPF.CIDRDecision
	sharedInitialDestinations []commonEBPF.CIDRDecision
	tcDataPlaneAccess         sync.RWMutex
	cgroupBackendAccess       sync.RWMutex
	cgroupReleaseWait         sync.WaitGroup
	cgroupRecoveryAccess      sync.Mutex
	cgroupRecoveryCancel      context.CancelFunc
	cgroupRecoveryDone        chan struct{}
	cgroupRecoveryEvents      chan commonEBPF.UDPReleaseEvent
	lifecycleAccess           sync.Mutex
	interfaceMonitor          tcInterfaceMonitor

	bypassRuleSetAccess sync.Mutex
	localBypassRules    bypassRuleSetState
	sharedBypassRules   bypassRuleSetState

	udpClientTable                udpClientTable
	udpReplySockets               udpReplySocketPool
	udpWarnings                   udpWarningLimiters
	tcpWarnings                   warningLimiter
	policyWarnings                warningLimiter
	interfaceWarnings             interfaceWarningLimiters
	diagnostics                   tcOutcomeHistory
	counters                      ebpfCounters
	tcReturnSweepEntries          atomic.Uint64
	tcReturnSweepCapacity         atomic.Uint64
	tcReturnSweepScanned          atomic.Uint64
	tcReturnSweepRemoved          atomic.Uint64
	tcAssignmentSweepUsageKnown   atomic.Bool
	tcReturnSweepUsageKnown       atomic.Bool
	tcAssignmentSweepFailureMap   atomic.Value
	tcAssignmentSweepScanned      atomic.Uint64
	tcAssignmentSweepRemoved      atomic.Uint64
	tcAssignmentSweepComplete     atomic.Bool
	tcAssignmentSweepEntries      atomic.Uint64
	tcAssignmentSweepCapacity     atomic.Uint64
	tcAssignmentSweepPressure     atomic.Bool
	tcAssignmentPressureRounds    atomic.Uint32
	tcAssignmentSweepRuns         atomic.Uint64
	tcAssignmentSweepPartial      atomic.Uint64
	tcAssignmentSweepFailure      atomic.Value
	tcAssignmentSweepLastAt       atomic.Int64
	tcAssignmentSweepPartialAt    atomic.Int64
	tcAssignmentWake              chan struct{}
	tcAssignmentJanitorAccess     sync.Mutex
	tcAssignmentJanitorCancel     context.CancelFunc
	tcAssignmentJanitorDone       chan struct{}
	cgroupRecoveryQueueOverflows  atomic.Uint64
	cgroupRecoveryQueueOverflowAt atomic.Int64
	// diagnosticsAPICache is request-driven only. API polling can be frequent,
	// so native per-CPU counter reads are coalesced for a short
	// window without adding a timer or background wakeup.
	diagnosticsAPIAccess sync.Mutex
	diagnosticsAPIAt     time.Time
	diagnosticsAPIValue  adapter.EBPFRuntimeDiagnostics
	// kernelRuntimeAPICache protects the more expensive global program/map
	// enumeration. It remains request-driven and never starts a timer.
	kernelRuntimeAPIAccess sync.Mutex
	kernelRuntimeAPIAt     time.Time
	kernelRuntimeAPIValue  adapter.EBPFKernelRuntimeDiagnostics
}

func (i *Inbound) localSocketAssignEnabled() bool {
	return i.localEnabled && i.localDataPlane == localDataPlaneSocketAssign
}
func (i *Inbound) socketAssignIPv6Enabled() bool {
	return i.localSocketAssignEnabled() && i.localIPv6 || i.sharedSocketAssignEnabled() && i.sharedIPv6
}
func (i *Inbound) localCgroupEnabled() bool {
	return i.localEnabled && i.localDataPlane == localDataPlaneCgroup
}
func (i *Inbound) sharedSocketAssignEnabled() bool {
	return i.sharedEnabled && i.sharedDataPlane == sharedDataPlaneSocketAssign
}
func (i *Inbound) sharedRewriteEnabled() bool {
	return i.sharedEnabled && i.sharedDataPlane == sharedDataPlanePacketRewrite
}

var _ adapter.InterfaceUpdateListener = (*Inbound)(nil)

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.EBPFInboundOptions) (adapter.Inbound, error) {
	selection, err := normalizeDataPlanes(options)
	if err != nil {
		return nil, err
	}
	localEnabled, sharedEnabled := selection.localEnabled, selection.sharedEnabled
	if err = validateLocalOptions(localEnabled, options.Local); err != nil {
		return nil, err
	}
	if err = validateSharedOptions(sharedEnabled, options.Shared); err != nil {
		return nil, err
	}
	if err = validateAndroidUIDOptions(runtime.GOOS, options.Local); err != nil {
		return nil, err
	}
	localDataPlane, cgroupPath, sharedDataPlane := selection.localDataPlane, selection.cgroupPath, selection.sharedDataPlane
	fakeIPICMPReply, err := normalizeFakeIPICMP(options.FakeIPICMP)
	if err != nil {
		return nil, E.Cause(err, "parse fakeip_icmp")
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
	localBypassExclude, err := normalizeCIDRs("local.bypass_exclude", options.Local.BypassExclude)
	if err != nil {
		return nil, err
	}
	sharedBypassExclude, err := normalizeCIDRs("shared.bypass_exclude", options.Shared.BypassExclude)
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
		localEnabled:        localEnabled,
		localDataPlane:      localDataPlane,
		cgroupPath:          cgroupPath,
		selfBypass:          selfBypass,
		processInfoCache:    newProcessInfoCache(),
		enableTCP:           enableTCP,
		enableUDP:           enableUDP,
		localDNSMode:        localDNSMode,
		sharedDNSMode:       sharedDNSMode,
		localIPv6:           localEnabled && enabledByDefault(options.Local.IPv6),
		sharedOptions:       sharedOptions,
		sharedEnabled:       sharedEnabled,
		sharedDataPlane:     sharedDataPlane,
		sharedIPv6:          sharedEnabled && enabledByDefault(options.Shared.IPv6),
		sharedBypassPrivate: options.Shared.BypassPrivateAddress == nil || *options.Shared.BypassPrivateAddress,
		localBypassPort:     localBypassPort,
		sharedBypassPort:    sharedBypassPort,
		localBypassExclude:  localBypassExclude,
		sharedBypassExclude: sharedBypassExclude,
		tcPriority:          uint16(options.TCPriority),
		sharedIncludeMAC:    sharedIncludeMAC,
		sharedExcludeMAC:    sharedExcludeMAC,
		localPolicy: localUIDPolicy{
			BypassPrivateAddress: options.Local.BypassPrivateAddress == nil || *options.Local.BypassPrivateAddress,
			IncludeUIDConfigured: len(options.Local.IncludeUID) > 0 ||
				len(options.Local.IncludeUIDRange) > 0 || len(options.Local.IncludePackage) > 0,
			IncludeUID: includeUIDRanges,
			ExcludeUID: excludeUIDRanges,
		},
		androidUIDOptions: newAndroidUIDOptions(options.Local),
		fakeIPICMPReply:   fakeIPICMPReply,
		tcAssignmentWake:  make(chan struct{}, 1),
	}
	if inbound.tcPriority == 0 {
		inbound.tcPriority = defaultTCPriority
	}
	inbound.tcAssignmentSweepFailure.Store("")
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
	if err = validateFakeIPICMP(
		fakeIPICMPReply, inbound.fakeIPIPv4Prefix, inbound.fakeIPIPv6Prefix,
		localEnabled, localDataPlane, sharedEnabled, sharedDataPlane,
	); err != nil {
		return nil, err
	}
	warnBypassPortConflicts(logger, "local", localDNSMode, localBypassPort)
	warnBypassPortConflicts(logger, "shared", sharedDNSMode, sharedBypassPort)
	loadRuleSets := func(scope string, target *[]adapter.RuleSet, tags ...[]string) error {
		seen := make(map[string]struct{})
		for _, tagList := range tags {
			for _, ruleSetTag := range tagList {
				if _, ok := seen[ruleSetTag]; ok {
					continue
				}
				seen[ruleSetTag] = struct{}{}
				ruleSet, loaded := router.RuleSet(ruleSetTag)
				if !loaded {
					return E.New("parse ", scope, ".bypass_rule_set: rule-set not found: ", ruleSetTag)
				}
				*target = append(*target, ruleSet)
			}
		}
		return nil
	}
	if err = loadRuleSets("local", &inbound.localBypassRules.ruleSets, options.Local.BypassRuleSet); err != nil {
		return nil, err
	}
	if err = loadRuleSets("shared", &inbound.sharedBypassRules.ruleSets, options.Shared.BypassRuleSet); err != nil {
		return nil, err
	}
	udpTimeout := C.UDPTimeout
	if options.UDPTimeout != 0 {
		udpTimeout = time.Duration(options.UDPTimeout)
	}
	if udpTimeout < 5*time.Second {
		return nil, E.New("eBPF UDP timeout must be at least 5s: ", udpTimeout)
	}
	inbound.udpTimeout = udpTimeout
	inbound.udpFragment = options.UDPFragment != nil && *options.UDPFragment
	if inbound.enableUDP && (inbound.localEnabled || inbound.sharedSocketAssignEnabled()) {
		inbound.udpNat = newUDPNATService(inbound, inbound.preparePacketConnection, udpTimeout)
	}
	return inbound, nil
}

func warnBypassPortConflicts(logger log.ContextLogger, scope, dnsMode string, ports []portRange) {
	if logger == nil || len(ports) == 0 {
		return
	}
	for _, portRange := range ports {
		if portRange.Start > 53 || portRange.End < 53 {
			continue
		}
		switch dnsMode {
		case dnsModeHijack:
			logger.Warn("eBPF ", scope, ".bypass_port includes DNS port 53, but dns_mode=hijack always intercepts it")
		case dnsModeRespectPolicy:
			logger.Warn("eBPF ", scope, ".bypass_port includes DNS port 53; dns_mode=respect_policy applies UID/source policy before DNS interception")
		case dnsModeOff:
			logger.Warn("eBPF ", scope, ".bypass_port includes DNS port 53, but dns_mode=off already bypasses DNS")
		}
		break
	}
}
