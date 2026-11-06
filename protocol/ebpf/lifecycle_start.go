//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"runtime"

	commonEBPF "github.com/CHIZI-0618/sing-ebpf"
	"github.com/sagernet/sing-box/adapter"
	E "github.com/sagernet/sing/common/exceptions"
)

func (i *Inbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	switch stage {
	case adapter.StartStateInitialize:
		if scope == nil {
			return E.New("missing eBPF inbound lifecycle scope")
		}
		// The adapter lifecycle owns cleanup through the child scope. Keep the
		// explicit startup rollback below as well: it gives direct callers and
		// failed starts an immediate retryable cleanup, while the scope remains
		// the final owner when Box.Start aborts or the box is closed.
		i.ctx = scope.Context()
		scope.Add(i.Close)
		if err := i.claimSelfBypass(); err != nil {
			return err
		}
		if err := retryRetainedInbounds(); err != nil {
			return err
		}
		if i.udpNat != nil {
			i.udpNat.start()
		}
		if i.localCgroupEnabled() || i.sharedRewriteEnabled() {
			if err := i.selectRedirectPrefixes(); err != nil {
				return err
			}
		}
		if i.localEnabled {
			if err := i.startSelfBypass(); err != nil {
				i.logger.Debug("eBPF cgroup self-bypass unavailable; using socket-cookie registration: ", err)
			}
		}
		return nil
	case adapter.StartStateStart:
	default:
		return nil
	}
	if err := i.startInbound(); err != nil {
		return combineStartError(err, i.cleanupStartFailure())
	}
	return nil
}

func (i *Inbound) startInbound() error {
	i.lifecycleAccess.Lock()
	defer i.lifecycleAccess.Unlock()
	i.interfaceWarnings.defaultInterfaceState.reset()
	if err := i.closeTCDataPlane(); err != nil {
		return E.Cause(err, "reclaim previous TC data plane")
	}
	if i.localEnabled && i.androidUIDOptions != nil {
		if err := i.resolveAndroidUIDPolicy(); err != nil {
			return E.Cause(err, "resolve Android UID policy")
		}
	}
	compiledPolicy, err := i.compileActionPolicy()
	if err != nil {
		return E.Cause(err, "compile eBPF policy")
	}
	i.compiledPolicy = compiledPolicy
	if err := i.checkKernelCapabilities(); err != nil {
		return err
	}
	if err := i.startProcessTracker(); err != nil {
		return err
	}
	defaultInterface := i.currentDefaultInterfaceName()
	hostAddresses := i.hostAddresses()
	localInterface := ""
	localSocketAssignEnabled := i.localSocketAssignEnabled()
	sharedSocketAssignEnabled := i.sharedSocketAssignEnabled()
	sharedRewriteEnabled := i.sharedRewriteEnabled()
	if localSocketAssignEnabled {
		localInterface = defaultInterface
	}
	sharedInterfaces := activeSharedInterfaces(i.sharedOptions.Interface, defaultInterface, i.sharedOptions.DefaultInterface)
	tcSharedInterfaces := []string(nil)
	if sharedSocketAssignEnabled {
		tcSharedInterfaces = sharedInterfaces
	}
	if err := i.startTCListenersIfNeeded(localSocketAssignEnabled, sharedSocketAssignEnabled); err != nil {
		return err
	}
	if err := i.startCgroupDataPlane(hostAddresses); err != nil {
		return err
	}
	if i.localCgroupEnabled() || sharedRewriteEnabled {
		if err := i.setupLocalRoutes(); err != nil {
			return E.Cause(err, "configure eBPF redirect routes")
		}
	}
	backend, dataPlane, err := i.startTCDataPlane(localInterface, tcSharedInterfaces, hostAddresses, localSocketAssignEnabled, sharedSocketAssignEnabled)
	if err != nil {
		return err
	}
	if err = i.startBypassRuleSets(); err != nil {
		return E.Cause(err, "initialize TC eBPF bypass_rule_set")
	}
	if sharedRewriteEnabled {
		if err = i.startSharedRewriteDataPlane(sharedInterfaces, hostAddresses); err != nil {
			return err
		}
	}
	if cgroupBackend := i.cgroupBackendInstance(); cgroupBackend != nil {
		if err = cgroupBackend.Attach(); err != nil {
			return err
		}
		i.startCgroupRecoveryScheduler(cgroupBackend)
		i.startCgroupUDPReleaseReader(cgroupBackend)
	}
	if backend != nil {
		if err = backend.Enable(); err != nil {
			return err
		}
	}
	if backend != nil && !i.sharedRewriteEnabled() {
		i.startTCAssignmentJanitor()
	}
	if backend != nil || i.cgroupBackendInstance() != nil || i.sharedRewriteInstance() != nil {
		if err = i.startTCInterfaceMonitor(); err != nil {
			return err
		}
	}
	network := "tcp"
	if i.enableTCP && i.enableUDP {
		network = "tcp,udp"
	} else if i.enableUDP {
		network = "udp"
	}
	if cgroupBackend := i.cgroupBackendInstance(); cgroupBackend != nil {
		i.logCgroupRuntime(network, cgroupBackend)
	}
	if dataPlane == nil && i.sharedRewriteInstance() == nil {
		i.logStartupSummaryLocked()
		return nil
	}
	tcNetworkInfo := commonEBPF.TCNetworkInfo{}
	if dataPlane != nil {
		tcNetworkInfo = dataPlane.NetworkInfo()
	}
	tcFields := map[string]any{
		"local_data_plane": func() string {
			if !i.localEnabled {
				return "off"
			}
			return i.localDataPlane
		}(),
		"shared_data_plane": func() string {
			if !i.sharedEnabled {
				return "off"
			}
			return i.sharedDataPlane
		}(),
		"network":          network,
		"local_ipv6":       i.localIPv6,
		"shared_ipv6":      i.sharedIPv6,
		"process_tracking": i.processTrackingMode(),
		"tc_priority":      i.tcPriority,
	}
	if selfBypass := i.selfBypassDiagnostics(); selfBypass.DecisionBackend != "" {
		tcFields["self_bypass_decision"] = selfBypass.DecisionBackend
		tcFields["self_bypass_producer"] = selfBypass.ProducerBackend
		tcFields["self_bypass_visibility"] = selfBypass.VisibilityBackend
		tcFields["self_bypass_cleanup"] = selfBypass.CleanupBackend
		tcFields["self_bypass_attachment"] = selfBypass.AttachmentBackend
		tcFields["self_bypass_reclaim"] = selfBypass.ReclaimBackend
	}
	if i.sharedEnabled {
		tcFields["shared_default_interface"] = i.sharedOptions.DefaultInterface
	}
	if defaultInterface != "" {
		tcFields["default_interface"] = defaultInterface
	}
	if localInterface != "" {
		tcFields["local_interface"] = localInterface
	}
	if len(i.sharedOptions.Interface) > 0 {
		tcFields["shared_interfaces"] = i.sharedOptions.Interface
	}
	if listeners := i.tcListeners.String(); listeners != "" {
		tcFields["tc_listeners"] = listeners
	}
	var attachments []commonEBPF.AttachmentInfo
	if dataPlane != nil {
		attachments = append(attachments, dataPlane.AttachmentDiagnostics()...)
	}
	if shared := i.sharedRewriteInstance(); shared != nil {
		if sharedDataPlane := shared.dataPlaneInstance(); sharedDataPlane != nil {
			attachments = append(attachments, sharedDataPlane.AttachmentDiagnostics()...)
		}
	}
	if len(attachments) > 0 {
		tcFields["attachments"] = attachments
	}
	if shared := i.sharedRewriteInstance(); shared != nil {
		if listeners := shared.listeners.String(); listeners != "" {
			tcFields["shared_rewrite_listeners"] = listeners
		}
	}
	if backend != nil {
		tcFields["tcp_listener_lookup"] = backend.TCPListenerLookupMode()
	}
	if tcNetworkInfo.Namespace != "" {
		tcFields["tc_namespace"] = "owned"
	}
	if tcNetworkInfo.DeliveryInterface != "" {
		tcFields["delivery_interface"] = tcNetworkInfo.DeliveryInterface
	}
	if tcNetworkInfo.RoutingMark != 0 {
		tcFields["routing_mark"] = fmt.Sprintf("0x%x", tcNetworkInfo.RoutingMark)
	}
	if tcNetworkInfo.RoutingTable != 0 {
		tcFields["routing_table"] = tcNetworkInfo.RoutingTable
	}
	if tcNetworkInfo.RoutingPriority != 0 {
		tcFields["routing_priority"] = tcNetworkInfo.RoutingPriority
	}
	i.logger.Debug("eBPF ", ebpfStructuredEvent("tc_runtime", tcFields))
	if i.enableUDP && (i.localSocketAssignEnabled() || i.sharedSocketAssignEnabled()) {
		i.udpReplySockets.startSweeper(i.ctx)
	}
	i.logStartupSummaryLocked()
	return nil
}

func (i *Inbound) startTCListenersIfNeeded(localEnabled, sharedEnabled bool) error {
	if !localEnabled && !sharedEnabled {
		return nil
	}
	return i.startTCListeners()
}

func (i *Inbound) startCgroupDataPlane(hostAddresses []netip.Addr) error {
	if !i.localCgroupEnabled() {
		return nil
	}
	if err := i.listeners.start(i.enableTCP, i.enableUDP, true, i.localIPv6, i.newListener, i.registerListenerSocket); err != nil {
		return err
	}
	if err := i.prepareCgroupBackend(); err != nil {
		return err
	}
	backend := i.cgroupBackendInstance()
	if err := backend.UpdateHostAddresses(hostAddresses); err != nil {
		return E.Cause(err, "initialize cgroup eBPF host address policy")
	}
	return backend.LoadPrograms(i.listeners.selectedPort())
}

func (i *Inbound) startTCDataPlane(
	localInterface string,
	sharedInterfaces []string,
	hostAddresses []netip.Addr,
	localEnabled, sharedEnabled bool,
) (*commonEBPF.TCBackend, tcRuntime, error) {
	backendConfig := commonEBPF.TCConfig{
		ListenerPort:      i.tcListeners.selectedPort(),
		EnableLocal:       localEnabled,
		EnableShared:      sharedEnabled,
		EnableIPv4:        true,
		EnableLocalIPv6:   localEnabled && i.localIPv6,
		EnableSharedIPv6:  sharedEnabled && i.sharedIPv6,
		EnableTCP:         i.enableTCP,
		EnableUDP:         i.enableUDP,
		Policy:            i.compiledPolicy,
		SelfBypass:        i.selfBypass,
		TrackProcess:      i.processTracker != nil,
		ICMPEchoReply:     i.fakeIPICMPReply,
		NetworkGeneration: uint32(i.currentNetworkGeneration()),
	}
	if backendConfig.NetworkGeneration == 0 {
		backendConfig.NetworkGeneration = 1
	}
	if runtime.GOOS == "android" {
		backendConfig.AssignmentCapacity = commonEBPF.CompactTCAssignmentCapacity
	}
	var err error
	var backend *commonEBPF.TCBackend
	if localEnabled || sharedEnabled {
		backend, err = commonEBPF.PrepareTC(backendConfig)
	}
	if err != nil && i.processTracker != nil {
		trackingErr := err
		var closeErr error
		i.processTracker, closeErr = closeProcessTrackerOwner(i.processTracker)
		if i.processTracker != nil {
			return nil, nil, E.Errors(trackingErr, E.Cause(closeErr, "cleanup eBPF process tracker"))
		}
		trackingErr = E.Errors(trackingErr, closeErr)
		backendConfig.TrackProcess = false
		backend, err = commonEBPF.PrepareTC(backendConfig)
		if err == nil {
			i.logger.Debug("eBPF cgroup process tracking unavailable; using userspace process search: ", trackingErr)
		}
	}
	if err != nil {
		return nil, nil, err
	}
	if backend == nil {
		return nil, nil, nil
	}
	if err = i.tcListeners.registerTCTCPListeners(backend); err != nil {
		i.setTCDataPlane(newUnstartedTCRuntime(backend))
		return nil, nil, E.Errors(err, i.closeTCDataPlane())
	}
	dataPlane, err := newTCRuntime(backend, tcRuntimeConfig{
		Namespace:             i.tcNamespace,
		IPv6Enabled:           i.socketAssignIPv6Enabled(),
		LocalInterface:        localInterface,
		SharedInterfaces:      sharedInterfaces,
		HostAddresses:         hostAddresses,
		SharedSourceMACPolicy: len(i.sharedIncludeMAC)+len(i.sharedExcludeMAC) > 0,
		Priority:              i.tcPriority,
	})
	i.setTCDataPlane(dataPlane)
	if err != nil {
		return nil, nil, err
	}
	i.warnIfLocalFakeIPICMPIPv6Unroutable(localInterface)
	return backend, dataPlane, nil
}

func (i *Inbound) startSharedRewriteDataPlane(sharedInterfaces []string, hostAddresses []netip.Addr) error {
	shared := newSharedRewrite(i, i.sharedOptions)
	i.setSharedRewrite(shared)
	return shared.Start(sharedInterfaces, hostAddresses)
}

// logCgroupRuntime records only cgroup-specific state. Keeping this separate
// from tc_runtime makes hybrid configurations readable and avoids repeating
// the same fields for every attached TC interface.
func (i *Inbound) logCgroupRuntime(network string, backend *commonEBPF.CgroupBackend) {
	if backend == nil {
		return
	}
	fields := map[string]any{
		"network":               network,
		"ipv6":                  i.cgroupIPv6Enabled(),
		"udp_cleanup":           backend.UDPCleanupMode(),
		"udp_time":              backend.UDPTimeMode(),
		"udp_storage":           backend.UDPStorageMode(),
		"userspace_udp_cleanup": backend.UDPUserspaceCleanupMode(),
		"process_tracking":      i.processTrackingMode(),
	}
	if selfBypass := i.selfBypassDiagnostics(); selfBypass.DecisionBackend != "" {
		fields["self_bypass_decision"] = selfBypass.DecisionBackend
		fields["self_bypass_producer"] = selfBypass.ProducerBackend
		fields["self_bypass_visibility"] = selfBypass.VisibilityBackend
		fields["self_bypass_cleanup"] = selfBypass.CleanupBackend
		fields["self_bypass_attachment"] = selfBypass.AttachmentBackend
		fields["self_bypass_reclaim"] = selfBypass.ReclaimBackend
	}
	if cgroup := backend.CgroupPath(); cgroup != "" {
		fields["cgroup"] = cgroup
	}
	if listeners := i.listeners.String(); listeners != "" {
		fields["listeners"] = listeners
	}
	if len(i.localPolicy.IncludeUID) > 0 {
		fields["uid_include"] = formatUIDRanges(i.localPolicy.IncludeUID)
	}
	if len(i.localPolicy.ExcludeUID) > 0 {
		fields["uid_exclude"] = formatUIDRanges(i.localPolicy.ExcludeUID)
	}
	i.logger.Debug("eBPF ", ebpfStructuredEvent("cgroup_runtime", fields))
}

func (i *Inbound) startProcessTracker() error {
	if !i.localEnabled || !i.router.NeedFindProcess() || i.usePlatformProcessFinder ||
		i.processTracker != nil || i.processTrackerRollback != nil {
		return nil
	}
	uidDecisions, defaultAction := i.compileProcessUIDPolicy()
	tracker, err := commonEBPF.AttachProcessTracker(commonEBPF.ProcessTrackerConfig{
		EnableTCP:    i.enableTCP,
		EnableUDP:    i.enableUDP,
		EnableIPv6:   i.localIPv6,
		UIDDecisions: uidDecisions,
		Default:      defaultAction,
		SelfBypass:   i.selfBypass,
	})
	if err != nil {
		if tracker != nil {
			i.processTrackerRollback = tracker
			return E.Cause(err, "rollback partial eBPF process tracker")
		}
		i.logger.Debug("eBPF cgroup process tracking unavailable; using userspace process search: ", err)
		return nil
	}
	i.processTracker = tracker
	return nil
}

func (i *Inbound) processTrackingMode() string {
	if i.usePlatformProcessFinder {
		return "platform"
	}
	if !i.localEnabled || !i.router.NeedFindProcess() {
		return "off"
	}
	if i.processTracker != nil {
		if i.processTracker.ReleaseCleanup() {
			return "cgroup_socket_release"
		}
		return "cgroup_socket_lru"
	}
	return "userspace"
}

func (i *Inbound) startCgroupUDPReleaseReader(backend *commonEBPF.CgroupBackend) {
	if backend == nil || backend.UDPUserspaceCleanupMode() != "ringbuf" {
		return
	}
	i.cgroupReleaseWait.Add(1)
	go func() {
		defer i.cgroupReleaseWait.Done()
		for {
			event, err := backend.ReadUDPRelease()
			if err != nil {
				if !errors.Is(err, os.ErrClosed) {
					i.logger.Warn("read cgroup eBPF UDP socket-release event: ", err)
				}
				return
			}
			i.udpNat.ReleaseSocket(event.SocketCookie)
			i.enqueueCgroupRecoveryEvent(backend, event)
		}
	}()
}

func (i *Inbound) selfBypassDiagnostics() commonEBPF.SelfBypassDiagnostics {
	if !i.localEnabled || i.selfBypass == nil {
		return commonEBPF.SelfBypassDiagnostics{}
	}
	return i.selfBypass.Diagnostics()
}

func (i *Inbound) startSelfBypass() error {
	if i.selfBypass == nil || i.selfBypassCgroup {
		return nil
	}
	if err := i.selfBypass.AttachCgroup(commonEBPF.SelfBypassCgroupConfig{
		EnableTCP:           i.enableTCP,
		EnableUDP:           i.enableUDP,
		EnableIPv6:          i.localIPv6,
		Direct:              i.localCgroupEnabled(),
		EnableSocketStorage: i.localSocketAssignEnabled(),
	}); err != nil {
		return err
	}
	i.selfBypassCgroup = true
	return nil
}

func (i *Inbound) checkKernelCapabilities() error {
	localSocketAssignEnabled := i.localSocketAssignEnabled()
	localCgroupEnabled := i.localCgroupEnabled()
	sharedSocketAssignEnabled := i.sharedSocketAssignEnabled()
	sharedRewriteEnabled := i.sharedRewriteEnabled()
	mode := commonEBPF.KernelProbeModeShared
	localSelected := localSocketAssignEnabled || localCgroupEnabled
	sharedSelected := sharedSocketAssignEnabled || sharedRewriteEnabled
	if localSelected && sharedSelected {
		mode = commonEBPF.KernelProbeModeAll
	} else if localSelected {
		mode = commonEBPF.KernelProbeModeLocal
	}
	network := make([]string, 0, 2)
	if i.enableTCP {
		network = append(network, "tcp")
	}
	if i.enableUDP {
		network = append(network, "udp")
	}
	localPlane := commonEBPF.KernelProbeDataPlane("")
	if localSocketAssignEnabled {
		localPlane = commonEBPF.KernelProbeDataPlaneSocketAssign
	} else if localCgroupEnabled {
		localPlane = commonEBPF.KernelProbeDataPlaneCgroup
	}
	sharedPlane := commonEBPF.KernelProbeDataPlane("")
	if sharedSocketAssignEnabled {
		sharedPlane = commonEBPF.KernelProbeDataPlaneSocketAssign
	} else if sharedRewriteEnabled {
		sharedPlane = commonEBPF.KernelProbeDataPlanePacketRewrite
	}
	report, err := commonEBPF.ProbeKernel(commonEBPF.KernelProbeOptions{
		Mode:                mode,
		LocalDataPlane:      localPlane,
		SharedDataPlane:     sharedPlane,
		Network:             network,
		InterfaceNames:      i.sharedOptions.Interface,
		CgroupPath:          i.cgroupPath,
		LocalInterface:      i.currentDefaultInterfaceName(),
		EnableIPv6:          (localSelected && i.localIPv6) || (sharedSelected && i.sharedIPv6),
		NeedLPMPolicy:       i.needsLPMPolicy(),
		NeedProcessTracking: localSelected && i.router.NeedFindProcess() && !i.usePlatformProcessFinder,
		ICMPEchoReply:       i.fakeIPICMPReply,
	})
	if err != nil {
		return E.Cause(err, "probe eBPF kernel capabilities")
	}
	if err = report.RequiredError(); err != nil {
		return E.Cause(err, "probe eBPF kernel capabilities")
	}
	return nil
}

func (i *Inbound) needsLPMPolicy() bool {
	if (i.localEnabled && (len(i.localBypassExclude) > 0 || i.localPolicy.BypassPrivateAddress)) ||
		(i.sharedEnabled && (len(i.sharedBypassExclude) > 0 || i.sharedBypassPrivate)) {
		return true
	}
	if (i.localEnabled && i.fakeIPForceInterceptRequired(false)) ||
		(i.sharedEnabled && i.fakeIPForceInterceptRequired(true)) {
		return true
	}
	if (i.localSocketAssignEnabled() || i.localCgroupEnabled()) &&
		(len(i.localPolicy.IncludeUID) > 0 || len(i.localPolicy.ExcludeUID) > 0) {
		return true
	}
	if (i.sharedSocketAssignEnabled() || i.sharedRewriteEnabled()) &&
		(len(i.sharedOptions.IncludeSourceCIDR) > 0 || len(i.sharedOptions.ExcludeSourceCIDR) > 0) {
		return true
	}
	// A configured eBPF bypass rule-set can publish CIDRs after a refresh even
	// when its current snapshot is empty, so reserve the LPM capability up front.
	if len(i.localBypassRules.ruleSets) > 0 || len(i.sharedBypassRules.ruleSets) > 0 {
		return true
	}
	return false
}

func combineStartError(startErr error, cleanupErr error) error {
	if cleanupErr == nil {
		return startErr
	}
	return E.Errors(startErr, E.Cause(cleanupErr, "cleanup eBPF inbound"))
}

// claimSelfBypass takes over the self-bypass prepared for this inbound once
// its cleanup is registered with the lifecycle scope. Until then the box
// closes an unclaimed tracker itself.
func (i *Inbound) claimSelfBypass() error {
	if i.selfBypass == nil {
		return nil
	}
	claimer, loaded := i.networkManager.(interface {
		ClaimEBPFSelfBypass(*commonEBPF.SelfBypass) bool
	})
	if !loaded {
		return nil
	}
	if !claimer.ClaimEBPFSelfBypass(i.selfBypass) {
		return E.New("eBPF self-bypass was released before the inbound initialized")
	}
	return nil
}
