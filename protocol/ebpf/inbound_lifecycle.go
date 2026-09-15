//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net/netip"
	"strconv"
	"strings"

	commonEBPF "github.com/CHIZI-0618/sing-ebpf"
	"github.com/sagernet/sing-box/adapter"
	E "github.com/sagernet/sing/common/exceptions"
)

func (i *Inbound) Start(stage adapter.StartStage) error {
	switch stage {
	case adapter.StartStateInitialize:
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
	if err := i.closeTCDataPlane(); err != nil {
		return E.Cause(err, "reclaim previous TC data plane")
	}
	if i.localEnabled && i.androidUIDOptions != nil {
		if err := i.resolveAndroidUIDPolicy(); err != nil {
			return E.Cause(err, "resolve Android UID policy")
		}
	}
	policy := i.localPolicy
	policy.EnableBypassCIDR = i.localCgroupEnabled()
	compiledPolicy, err := commonEBPF.CompilePolicy(commonEBPF.PolicyConfig{
		EnableTCP:           i.enableTCP,
		EnableUDP:           i.enableUDP,
		Local:               policy,
		SharedDNSMode:       toCommonDNSMode(i.sharedDNSMode),
		SharedBypassPrivate: i.sharedBypassPrivate,
		ForceInterceptIPv4:  i.fakeIPIPv4Prefix,
		ForceInterceptIPv6:  i.fakeIPIPv6Prefix,
		IncludeSourceCIDR:   i.sharedOptions.IncludeSourceCIDR,
		ExcludeSourceCIDR:   i.sharedOptions.ExcludeSourceCIDR,
		IncludeSourceMAC:    i.sharedIncludeMAC,
		ExcludeSourceMAC:    i.sharedExcludeMAC,
		LocalBypassPort:     i.localBypassPort,
		SharedBypassPort:    i.sharedBypassPort,
	})
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
	localTCEnabled := i.localTCEnabled()
	sharedSocketAssignEnabled := i.sharedSocketAssignEnabled()
	sharedRewriteEnabled := i.sharedRewriteEnabled()
	if localTCEnabled {
		localInterface = defaultInterface
		if localInterface == "" {
			i.logger.Warn("default interface unavailable; local TC eBPF interception is paused")
		}
	}
	sharedInterfaces := activeSharedInterfaces(i.sharedOptions.Interface, defaultInterface)
	tcSharedInterfaces := []string(nil)
	if sharedSocketAssignEnabled {
		tcSharedInterfaces = sharedInterfaces
	}
	if i.localEnabled || sharedSocketAssignEnabled {
		if err := i.startTCListeners(); err != nil {
			return err
		}
	}
	if i.localCgroupEnabled() {
		if err := i.prepareCgroupBackend(); err != nil {
			return err
		}
		cgroupBackend := i.cgroupBackendInstance()
		if err := cgroupBackend.UpdateHostAddresses(hostAddresses); err != nil {
			return E.Cause(err, "initialize cgroup eBPF host address policy")
		}
		if err := cgroupBackend.LoadPrograms(i.listeners.selectedPort()); err != nil {
			return err
		}
	}
	if i.localCgroupEnabled() || sharedRewriteEnabled {
		if err := i.setupLocalRoutes(); err != nil {
			return E.Cause(err, "configure eBPF redirect routes")
		}
	}
	backendConfig := commonEBPF.TCConfig{
		ListenerPort:     i.listeners.selectedPort(),
		EnableLocal:      localTCEnabled,
		EnableShared:     sharedSocketAssignEnabled,
		EnableIPv4:       true,
		EnableLocalIPv6:  i.localIPv6,
		EnableSharedIPv6: i.sharedIPv6,
		EnableTCP:        i.enableTCP,
		EnableUDP:        i.enableUDP,
		Policy:           i.compiledPolicy,
		SelfBypass:       i.selfBypass,
		TrackProcess:     i.processTracker != nil,
		ICMPEchoReply:    i.fakeIPICMPReply,
	}
	var backend *commonEBPF.TCBackend
	if localTCEnabled || sharedSocketAssignEnabled {
		backend, err = commonEBPF.PrepareTC(backendConfig)
	}
	if err != nil && i.processTracker != nil {
		trackingErr := err
		var closeErr error
		i.processTracker, closeErr = closeProcessTrackerOwner(i.processTracker)
		if i.processTracker != nil {
			return E.Errors(trackingErr, E.Cause(closeErr, "cleanup eBPF process tracker"))
		}
		trackingErr = E.Errors(trackingErr, closeErr)
		backendConfig.TrackProcess = false
		backend, err = commonEBPF.PrepareTC(backendConfig)
		if err == nil {
			i.logger.Debug("eBPF cgroup process tracking unavailable; using userspace process search: ", trackingErr)
		}
	}
	if err != nil {
		return err
	}
	if backend != nil {
		if err = i.listeners.registerTCTCPListeners(backend); err != nil {
			i.setTCDataPlane(newUnstartedTCRuntime(backend))
			return E.Errors(err, i.closeTCDataPlane())
		}
	}
	var dataPlane tcRuntime
	if backend != nil {
		tcIPv6Enabled := localTCEnabled && i.localIPv6 || sharedSocketAssignEnabled && i.sharedIPv6
		dataPlane, err = newTCRuntime(backend, tcRuntimeConfig{
			LocalEnabled:          localTCEnabled,
			IPv6Enabled:           tcIPv6Enabled,
			LocalInterface:        localInterface,
			SharedInterfaces:      tcSharedInterfaces,
			HostAddresses:         hostAddresses,
			SharedSourceMACPolicy: len(i.sharedIncludeMAC)+len(i.sharedExcludeMAC) > 0,
			Priority:              i.tcPriority,
		})
		i.setTCDataPlane(dataPlane)
		if err != nil {
			return err
		}
		i.warnIfLocalFakeIPICMPIPv6Unroutable(localInterface)
	}
	if err = i.startBypassRuleSets(); err != nil {
		return E.Cause(err, "initialize TC eBPF bypass_rule_set")
	}
	if sharedRewriteEnabled {
		shared := newSharedRewrite(i, i.sharedOptions)
		i.setSharedRewrite(shared)
		if err = shared.Start(sharedInterfaces, hostAddresses); err != nil {
			return err
		}
	}
	if cgroupBackend := i.cgroupBackendInstance(); cgroupBackend != nil {
		if err = cgroupBackend.Attach(); err != nil {
			return err
		}
	}
	if backend != nil {
		if err = backend.Enable(); err != nil {
			return err
		}
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
	if dataPlane == nil && i.sharedRewriteInstance() == nil {
		cgroupBackend := i.cgroupBackendInstance()
		i.logger.Debug(
			"eBPF cgroup active: network=", network,
			", cgroup=", cgroupBackend.CgroupPath(),
			", ipv6=", i.cgroupIPv6Enabled(),
			", listeners=[", i.listeners.String(), "]",
			", udp_cleanup=", cgroupBackend.UDPCleanupMode(),
			", udp_time=", cgroupBackend.UDPTimeMode(),
			", udp_storage=", cgroupBackend.UDPStorageMode(),
			", local_uid_include=", formatUIDRanges(i.localPolicy.IncludeUID),
			", local_uid_exclude=", formatUIDRanges(i.localPolicy.ExcludeUID),
			", self_bypass=", i.selfBypassMode(),
			", process_tracking=", i.processTrackingMode(),
		)
		i.logStartupSummary()
		return nil
	}
	tcNetworkInfo := commonEBPF.TCNetworkInfo{}
	if dataPlane != nil {
		tcNetworkInfo = dataPlane.NetworkInfo()
	}
	i.logger.Debug(
		"eBPF TC active: local_data_plane=", func() string {
			if !i.localEnabled {
				return "off"
			}
			return i.localDataPlane
		}(),
		", local_cgroup=", func() string {
			if cgroupBackend := i.cgroupBackendInstance(); cgroupBackend != nil {
				return cgroupBackend.CgroupPath()
			}
			return ""
		}(),
		", local_cgroup_udp_time=", func() string {
			if cgroupBackend := i.cgroupBackendInstance(); cgroupBackend != nil {
				return cgroupBackend.UDPTimeMode()
			}
			return "disabled"
		}(),
		", local_cgroup_udp_cleanup=", func() string {
			if cgroupBackend := i.cgroupBackendInstance(); cgroupBackend != nil {
				return cgroupBackend.UDPCleanupMode()
			}
			return "disabled"
		}(),
		", local_cgroup_udp_storage=", func() string {
			if cgroupBackend := i.cgroupBackendInstance(); cgroupBackend != nil {
				return cgroupBackend.UDPStorageMode()
			}
			return "disabled"
		}(),
		", shared_data_plane=", func() string {
			if !i.sharedEnabled {
				return "off"
			}
			return i.sharedDataPlane
		}(),
		", network=", network,
		", local_ipv6=", i.localIPv6,
		", shared_ipv6=", i.sharedIPv6,
		", default_interface=", defaultInterface,
		", local_interface=", localInterface,
		", shared_interfaces=[", strings.Join(i.sharedOptions.Interface, ", "), "]",
		", attachments=[", func() string {
			var attachments []string
			if dataPlane != nil {
				attachments = append(attachments, dataPlane.AttachmentDescriptions()...)
			}
			if shared := i.sharedRewriteInstance(); shared != nil {
				if sharedDataPlane := shared.dataPlaneInstance(); sharedDataPlane != nil {
					attachments = append(attachments, sharedDataPlane.AttachmentDescriptions()...)
				}
			}
			return strings.Join(attachments, ", ")
		}(), "]",
		", listeners=[", i.listeners.String(), "]",
		", local_uid_include=", formatUIDRanges(i.localPolicy.IncludeUID),
		", local_uid_exclude=", formatUIDRanges(i.localPolicy.ExcludeUID),
		", shared_rewrite_listeners=[", func() string {
			shared := i.sharedRewriteInstance()
			if shared == nil {
				return ""
			}
			return shared.listeners.String()
		}(), "]",
		", tcp_listener_lookup=", func() string {
			if backend == nil {
				return "none"
			}
			return backend.TCPListenerLookupMode()
		}(),
		", delivery_interface=", func() string {
			return tcNetworkInfo.DeliveryInterface
		}(),
		", routing_mark=", func() string {
			if tcNetworkInfo.RoutingMark == 0 {
				return ""
			}
			return "0x" + strconv.FormatUint(uint64(tcNetworkInfo.RoutingMark), 16)
		}(),
		", routing_table=", func() string {
			if tcNetworkInfo.RoutingTable == 0 {
				return ""
			}
			return strconv.Itoa(tcNetworkInfo.RoutingTable)
		}(),
		", routing_priority=", func() string {
			if tcNetworkInfo.RoutingPriority == 0 {
				return ""
			}
			return strconv.Itoa(tcNetworkInfo.RoutingPriority)
		}(),
		", self_bypass=", i.selfBypassMode(),
		", process_tracking=", i.processTrackingMode(),
		", tc_priority=", i.tcPriority,
	)
	i.udpReplySockets.startSweeper(i.ctx)
	i.logStartupSummary()
	return nil
}

func (i *Inbound) startProcessTracker() error {
	if !i.localEnabled || !i.router.NeedFindProcess() || i.usePlatformProcessFinder ||
		i.processTracker != nil || i.processTrackerRollback != nil {
		return nil
	}
	tracker, err := commonEBPF.AttachProcessTracker(commonEBPF.ProcessTrackerConfig{
		EnableTCP:   i.enableTCP,
		EnableUDP:   i.enableUDP,
		EnableIPv6:  i.localIPv6,
		LocalPolicy: i.localPolicy,
		SelfBypass:  i.selfBypass,
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

func (i *Inbound) selfBypassMode() string {
	if !i.localEnabled || i.selfBypass == nil {
		return "none"
	}
	if i.selfBypassCgroup {
		return i.selfBypass.Mode().String()
	}
	return "userspace_socket_cookie"
}

func (i *Inbound) startSelfBypass() error {
	if i.selfBypass == nil || i.selfBypassCgroup {
		return nil
	}
	if err := i.selfBypass.AttachCgroup(commonEBPF.SelfBypassCgroupConfig{
		EnableTCP:  i.enableTCP,
		EnableUDP:  i.enableUDP,
		EnableIPv6: i.localIPv6,
	}); err != nil {
		return err
	}
	i.selfBypassCgroup = true
	return nil
}

func (i *Inbound) checkKernelCapabilities() error {
	localTCEnabled := i.localTCEnabled()
	localCgroupEnabled := i.localCgroupEnabled()
	sharedSocketAssignEnabled := i.sharedSocketAssignEnabled()
	sharedRewriteEnabled := i.sharedRewriteEnabled()
	mode := commonEBPF.KernelProbeModeShared
	localSelected := localTCEnabled || localCgroupEnabled
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
	if localTCEnabled {
		localPlane = commonEBPF.KernelProbeDataPlaneTC
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
	if (i.localTCEnabled() || i.localCgroupEnabled()) &&
		(len(i.localPolicy.IncludeUID) > 0 || len(i.localPolicy.ExcludeUID) > 0) {
		return true
	}
	if (i.sharedSocketAssignEnabled() || i.sharedRewriteEnabled()) &&
		(len(i.sharedOptions.IncludeSourceCIDR) > 0 || len(i.sharedOptions.ExcludeSourceCIDR) > 0) {
		return true
	}
	for _, ruleSet := range i.bypassRuleSet {
		for _, ipSet := range ruleSet.ExtractIPSet() {
			if len(ipSet.Prefixes()) > 0 {
				return true
			}
		}
	}
	return false
}

func combineStartError(startErr error, cleanupErr error) error {
	if cleanupErr == nil {
		return startErr
	}
	return E.Errors(startErr, E.Cause(cleanupErr, "cleanup eBPF inbound"))
}

func (i *Inbound) Close() error {
	i.lifecycleAccess.Lock()
	defer i.lifecycleAccess.Unlock()
	return i.closeResources()
}

func (i *Inbound) cleanupStartFailure() error {
	return i.closeResources()
}

func (i *Inbound) closeResources() error {
	monitorErr := i.stopTCInterfaceMonitor()
	i.stopBypassRuleSets()
	sharedRewriteErr := error(nil)
	if shared := i.takeSharedRewrite(); shared != nil {
		sharedRewriteErr = shared.Close()
	}
	dataPlane := i.takeTCDataPlane()
	disableErr := error(nil)
	if dataPlane != nil {
		disableErr = dataPlane.Disable()
	}
	cgroupBackend := i.takeCgroupBackend()
	cgroupErr := error(nil)
	if cgroupBackend != nil {
		cgroupErr = cgroupBackend.Close()
		// Close keeps the runtime when a program could not be detached, because a
		// legacy cgroup attachment is owned by the cgroup rather than by the
		// program handle: dropping the handles would leave that program attached
		// with nothing able to detach it. Take the backend back so a later close
		// can retry the slots that failed.
		if !cgroupBackend.IsClosed() {
			i.setCgroupBackend(cgroupBackend)
			if cgroupErr == nil {
				cgroupErr = E.New("cgroup eBPF backend remained open after close")
			}
		}
	}
	listenerErr := i.closeListeners()
	i.udpNat.Purge()
	i.udpReplySockets.stopSweeper()
	udpReplySocketErr := i.udpReplySockets.close()
	dataPlaneErr := i.closeTakenTCDataPlane(dataPlane)
	routeErr := i.removeLocalRoutes()
	selfBypassErr := error(nil)
	if i.selfBypass != nil {
		if clearer, loaded := i.networkManager.(interface {
			ClearEBPFSelfBypass(*commonEBPF.SelfBypass)
		}); loaded {
			clearer.ClearEBPFSelfBypass(i.selfBypass)
		}
		selfBypassErr = i.selfBypass.Close()
		if i.selfBypass.IsClosed() {
			i.selfBypass = nil
		} else if selfBypassErr == nil {
			selfBypassErr = E.New("eBPF self-bypass remained open after close")
		}
	}
	processTrackerErr := error(nil)
	if i.processTracker != nil {
		i.processTracker, processTrackerErr = closeProcessTrackerOwner(i.processTracker)
	}
	processTrackerRollbackErr := error(nil)
	if i.processTrackerRollback != nil {
		i.processTrackerRollback, processTrackerRollbackErr = closeProcessTrackerOwner(i.processTrackerRollback)
	}
	return E.Errors(monitorErr, sharedRewriteErr, disableErr, listenerErr, udpReplySocketErr, dataPlaneErr, cgroupErr, routeErr, processTrackerErr, processTrackerRollbackErr, selfBypassErr)
}

func closeProcessTrackerOwner(tracker processTrackerOwner) (processTrackerOwner, error) {
	if tracker == nil {
		return nil, nil
	}
	closeErr := tracker.Close()
	if tracker.IsClosed() {
		return nil, closeErr
	}
	if closeErr == nil {
		closeErr = E.New("eBPF process tracker remained open after close")
	}
	return tracker, closeErr
}

func (i *Inbound) prepareCgroupBackend() error {
	if err := i.reclaimCgroupBackend(); err != nil {
		return err
	}
	backend, err := commonEBPF.PrepareCgroup(commonEBPF.CgroupConfig{
		Path:         i.cgroupPath,
		EnableTCP:    i.enableTCP,
		EnableUDP:    i.enableUDP,
		EnableIPv6:   i.cgroupIPv6Enabled(),
		RedirectIPv4: i.redirectIPv4Prefix,
		RedirectIPv6: i.redirectIPv6Prefix,
		MapCapacity:  commonEBPF.DefaultCgroupMapCapacity(),
		UDPTimeout:   i.udpTimeout,
		Policy:       i.compiledPolicy,
		SelfBypass:   i.selfBypass,
	})
	if err != nil {
		return err
	}
	i.setCgroupBackend(backend)
	return nil
}

func (i *Inbound) tcBackend() *commonEBPF.TCBackend {
	i.tcDataPlaneAccess.RLock()
	defer i.tcDataPlaneAccess.RUnlock()
	if i.tcDataPlane == nil {
		return nil
	}
	return i.tcDataPlane.Backend()
}

// cgroupBackendCloser is the part of a retained backend the reclaim needs, so
// the decision can be exercised without loading one.
type cgroupBackendCloser interface {
	Close() error
	IsClosed() bool
	CgroupPath() string
}

// reclaimCgroupBackendState retries the close of a retained backend and reports
// whether it finished. It is a variable so tests can drive both outcomes.
var reclaimCgroupBackendState = func(backend cgroupBackendCloser) (bool, error) {
	closeErr := backend.Close()
	if backend.IsClosed() {
		return true, closeErr
	}
	return false, E.Errors(
		E.New("cgroup eBPF backend from a previous run is still attached to ", backend.CgroupPath()),
		closeErr,
	)
}

// reclaimCgroupBackend finishes with a backend a previous close could not,
// before a new one is prepared.
//
// Close keeps its runtime when a program could not be detached, so the handles a
// retry needs stay owned, and closeResources hands the backend back for that
// reason. Nothing retries it on its own. Two things follow from leaving it
// alone, and they are different problems.
//
// On the same cgroup, the retained handle still holds the exclusive lock
// PrepareCgroup takes, so preparing a replacement fails at the lock and reports
// the cgroup as belonging to someone else. Nothing is overwritten there, because
// the assignment only happens once PrepareCgroup has succeeded; the start simply
// cannot proceed. On a different cgroup, PrepareCgroup does succeed and the
// assignment then replaces the retained backend, which is where a reference is
// genuinely dropped.
//
// Retrying here covers both: starting up is when the lifecycle is available
// again, and this is the same close it already performs. A backend that still
// will not close is handed back rather than dropped, and the error says what is
// actually wrong instead of letting the lock failure report it as somebody
// else's cgroup.
func (i *Inbound) reclaimCgroupBackend() error {
	retained := i.takeCgroupBackend()
	if retained == nil {
		return nil
	}
	reclaimed, err := reclaimCgroupBackendState(retained)
	if !reclaimed {
		i.setCgroupBackend(retained)
	}
	return err
}

func (i *Inbound) cgroupBackendInstance() *commonEBPF.CgroupBackend {
	i.cgroupBackendAccess.RLock()
	defer i.cgroupBackendAccess.RUnlock()
	return i.cgroupBackend
}

func (i *Inbound) setCgroupBackend(backend *commonEBPF.CgroupBackend) {
	i.cgroupBackendAccess.Lock()
	i.cgroupBackend = backend
	i.cgroupBackendAccess.Unlock()
}

func (i *Inbound) takeCgroupBackend() *commonEBPF.CgroupBackend {
	i.cgroupBackendAccess.Lock()
	backend := i.cgroupBackend
	i.cgroupBackend = nil
	i.cgroupBackendAccess.Unlock()
	return backend
}

func (i *Inbound) isCgroupRedirectAddress(address netip.Addr) bool {
	address = address.Unmap()
	if address.Is4() {
		return i.redirectIPv4Prefix.IsValid() && i.redirectIPv4Prefix.Contains(address)
	}
	return address.Is6() && i.redirectIPv6Prefix.IsValid() && i.redirectIPv6Prefix.Contains(address)
}

// sharedRewriteInstance, setSharedRewrite, and takeSharedRewrite guard
// i.sharedRewrite the same way tcDataPlaneAccess guards i.tcDataPlane below:
// Diagnostics can be called at any time from an HTTP handler with no
// relationship to this inbound's own lifecycle, so a plain field read there
// races against closeResources' plain field write with nothing else
// coincidentally serializing the two -- confirmed with go test -race.
func (i *Inbound) sharedRewriteInstance() *sharedRewrite {
	i.sharedRewriteAccess.RLock()
	defer i.sharedRewriteAccess.RUnlock()
	return i.sharedRewrite
}

func (i *Inbound) setSharedRewrite(shared *sharedRewrite) {
	i.sharedRewriteAccess.Lock()
	i.sharedRewrite = shared
	i.sharedRewriteAccess.Unlock()
}

func (i *Inbound) takeSharedRewrite() *sharedRewrite {
	i.sharedRewriteAccess.Lock()
	shared := i.sharedRewrite
	i.sharedRewrite = nil
	i.sharedRewriteAccess.Unlock()
	return shared
}

func (i *Inbound) setTCDataPlane(dataPlane tcRuntime) {
	i.tcDataPlaneAccess.Lock()
	i.tcDataPlane = dataPlane
	i.tcDataPlaneAccess.Unlock()
}

func (i *Inbound) takeTCDataPlane() tcRuntime {
	i.tcDataPlaneAccess.Lock()
	dataPlane := i.tcDataPlane
	i.tcDataPlane = nil
	i.tcDataPlaneAccess.Unlock()
	return dataPlane
}

func (i *Inbound) reconcileTCDataPlane(localInterface string, sharedInterfaces []string, hostAddresses []netip.Addr) error {
	i.tcDataPlaneAccess.RLock()
	defer i.tcDataPlaneAccess.RUnlock()
	if i.tcDataPlane == nil {
		return nil
	}
	return i.tcDataPlane.Reconcile(localInterface, sharedInterfaces, hostAddresses)
}

// Keep the owner reachable after both normal shutdown and startup cleanup.
func (i *Inbound) closeTakenTCDataPlane(dataPlane tcRuntime) error {
	if dataPlane == nil {
		return nil
	}
	err := dataPlane.Close()
	if !dataPlane.IsClosed() {
		i.setTCDataPlane(dataPlane)
		if err == nil {
			err = E.New("TC eBPF data plane remained open after close")
		}
	}
	return err
}

func (i *Inbound) closeTCDataPlane() error {
	return i.closeTakenTCDataPlane(i.takeTCDataPlane())
}
