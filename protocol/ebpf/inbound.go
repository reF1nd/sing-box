//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"net/netip"
	"runtime"
	"sync"
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
	"github.com/sagernet/sing/common/x/list"
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
	ctx                      context.Context
	router                   adapter.Router
	logger                   log.ContextLogger
	networkManager           adapter.NetworkManager
	localEnabled             bool
	localDataPlane           string
	cgroupPath               string
	cgroupBackend            *commonEBPF.CgroupBackend
	localRoutes              *commonEBPF.LocalRouteSet
	redirectIPv4Prefix       netip.Prefix
	redirectIPv6Prefix       netip.Prefix
	selfBypass               *commonEBPF.SelfBypass
	selfBypassCgroup         bool
	processTracker           processTrackerOwner
	processTrackerRollback   processTrackerOwner
	processInfoCache         *processInfoCache
	usePlatformProcessFinder bool
	listeners                internalListenerSet
	udpNat                   *udpNATService
	tcDataPlane              tcRuntime
	udpTimeout               time.Duration
	enableTCP                bool
	enableUDP                bool
	localDNSMode             string
	sharedDNSMode            string
	localIPv6                bool
	localPolicy              commonEBPF.LocalPolicy
	compiledPolicy           commonEBPF.CompiledPolicy
	androidUIDOptions        *androidUIDOptions
	sharedOptions            option.EBPFSharedOptions
	sharedEnabled            bool
	sharedDataPlane          string
	sharedRewrite            *sharedRewrite
	sharedRewriteAccess      sync.RWMutex
	sharedIPv6               bool
	sharedBypassPrivate      bool
	localBypassPort          []commonEBPF.PortRange
	sharedBypassPort         []commonEBPF.PortRange
	tcPriority               uint16
	fakeIPIPv4Prefix         netip.Prefix
	fakeIPIPv6Prefix         netip.Prefix
	fakeIPICMPReply          bool
	sharedIncludeMAC         []commonEBPF.MACAddress
	sharedExcludeMAC         []commonEBPF.MACAddress
	tcDataPlaneAccess        sync.RWMutex
	cgroupBackendAccess      sync.RWMutex
	lifecycleAccess          sync.Mutex
	interfaceMonitor         tcInterfaceMonitor
	networkStateInitialized  bool
	networkStateDefault      string
	networkStateAddresses    []netip.Addr
	networkStateInterfaces   []string

	bypassRuleSetAccess       sync.Mutex
	bypassRuleSet             []adapter.RuleSet
	bypassRuleSetCallbacks    []*list.Element[adapter.RuleSetUpdateCallback]
	bypassRuleSetStarted      bool
	bypassRuleSetPolicy       commonEBPF.BypassCIDRPolicy
	bypassRuleSetNeedsRetry   bool
	bypassRuleSetInconsistent bool
	// bypassRuleSetExpectedPolicy is the content applyBypassCIDRPolicyLocked
	// most recently attempted, successful or not -- see
	// bypassRuleSetExpectedVersion's doc comment below for why a version
	// number needs its own content to compare each new attempt against,
	// distinct from bypassRuleSetPolicy (the last CONFIRMED content).
	bypassRuleSetExpectedPolicy commonEBPF.BypassCIDRPolicy
	// bypassRuleSetPolicyVersion is the compiled bypass_rule_set policy's own
	// content-based version: it advances only when a newly compiled policy
	// actually differs (by value, via reflect.DeepEqual) from the one
	// currently in effect, so it answers "which policy generation is this",
	// not "how many times has an apply been attempted" -- retrying the same
	// compiled content after a failure does not advance it. It is committed
	// only alongside bypassRuleSetPolicy itself, on a fully successful apply
	// -- so together they name the policy this inbound has actually
	// confirmed applying, the "last successfully applied" state.
	//
	// bypassRuleSetExpectedVersion is the different thing a diagnostics
	// reader needs while a retry is outstanding: the version of the most
	// recently ATTEMPTED policy, updated unconditionally on every call to
	// applyBypassCIDRPolicyLocked regardless of whether that attempt
	// succeeded -- the "what we are currently trying to converge to"
	// state. While bypassRuleSetNeedsRetry is true,
	// bypassRuleSetExpectedVersion names the target a later retry is
	// chasing; bypassRuleSetPolicyVersion still names whatever was last
	// actually confirmed, which lags behind it by construction. The two
	// coincide exactly when nothing is currently pending: that is what
	// "caught up" means here, not any particular field's value in
	// isolation.
	//
	// bypassRuleSetRetryCount is scoped precisely to retries:
	// retryBypassRuleSetIfNeededLocked is the only place that increments
	// it, so it counts scheduler-driven retries of a previously-failed
	// apply specifically, not the original attempt and not a fresh apply
	// triggered by rule-set content actually changing.
	//
	// The three backend fields below record, per backend, its own
	// confirmed position in the policy version sequence (i.e. relative to
	// bypassRuleSetPolicyVersion, not bypassRuleSetExpectedVersion) -- see
	// bypassRuleSetBackendVersion's doc comment for what "confirmed" means
	// and does not mean once a compensating revert has failed.
	bypassRuleSetPolicyVersion   uint64
	bypassRuleSetExpectedVersion uint64
	bypassRuleSetRetryCount      uint64
	bypassRuleSetTC              bypassRuleSetBackendVersion
	bypassRuleSetCgroup          bypassRuleSetBackendVersion
	bypassRuleSetShared          bypassRuleSetBackendVersion

	udpClientTable    udpClientTable
	udpReplySockets   udpReplySocketPool
	udpWarnings       udpWarningLimiters
	tcpWarnings       warningLimiter
	policyWarnings    warningLimiter
	interfaceWarnings interfaceWarningLimiters
	diagnostics       tcOutcomeHistory
	counters          ebpfCounters
}

func (i *Inbound) localTCEnabled() bool {
	return i.localEnabled && i.localDataPlane == localDataPlaneTC
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
		fakeIPICMPReply:   fakeIPICMPReply,
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
	if err = validateFakeIPICMP(
		fakeIPICMPReply, inbound.fakeIPIPv4Prefix, inbound.fakeIPIPv6Prefix,
		localEnabled, localDataPlane, sharedEnabled, sharedDataPlane,
	); err != nil {
		return nil, err
	}
	warnBypassPortConflicts(logger, "local", localDNSMode, localBypassPort)
	warnBypassPortConflicts(logger, "shared", sharedDNSMode, sharedBypassPort)
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
	inbound.udpNat = newUDPNATService(inbound, inbound.preparePacketConnection, udpTimeout)
	return inbound, nil
}

func warnBypassPortConflicts(logger log.ContextLogger, scope, dnsMode string, ports []commonEBPF.PortRange) {
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
