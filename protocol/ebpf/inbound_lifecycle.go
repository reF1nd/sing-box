//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net/netip"
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	commonEBPF "github.com/sagernet/sing-box/common/ebpf"
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
		FakeIPIPv4:          i.fakeIPIPv4Prefix,
		FakeIPIPv6:          i.fakeIPIPv6Prefix,
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
	i.startProcessTracker()
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
		SelfBypassMap:    i.selfBypass.Map(),
		TrackProcess:     i.processTracker != nil,
	}
	var backend *commonEBPF.TCBackend
	if localTCEnabled || sharedSocketAssignEnabled {
		backend, err = commonEBPF.PrepareTC(backendConfig)
	}
	if err != nil && i.processTracker != nil {
		trackingErr := err
		_ = i.processTracker.Close()
		i.processTracker = nil
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
			return E.Errors(err, backend.Close())
		}
	}
	var dataPlane *tcDataPlane
	if backend != nil {
		tcIPv6Enabled := localTCEnabled && i.localIPv6 || sharedSocketAssignEnabled && i.sharedIPv6
		dataPlane, err = startTCDataPlane(
			backend,
			localTCEnabled,
			tcIPv6Enabled,
			localInterface,
			tcSharedInterfaces,
			hostAddresses,
			len(i.sharedIncludeMAC)+len(i.sharedExcludeMAC) > 0,
			i.tcPriority,
		)
		if err != nil {
			return err
		}
		i.setTCDataPlane(dataPlane)
	}
	if err = i.startBypassRuleSets(); err != nil {
		return E.Cause(err, "initialize TC eBPF bypass_rule_set")
	}
	if sharedRewriteEnabled {
		i.sharedRewrite = newSharedRewrite(i, i.sharedOptions)
		if err = i.sharedRewrite.Start(sharedInterfaces, hostAddresses); err != nil {
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
	if backend != nil || i.cgroupBackendInstance() != nil || i.sharedRewrite != nil {
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
	if dataPlane == nil && i.sharedRewrite == nil {
		cgroupBackend := i.cgroupBackendInstance()
		i.logger.Debug(
			"eBPF cgroup active: network=", network,
			", cgroup=", cgroupBackend.CgroupPath(),
			", ipv6=", i.cgroupIPv6Enabled(),
			", listeners=[", i.listeners.String(), "]",
			", udp_cleanup=", cgroupBackend.UDPCleanupMode(),
			", udp_time=", cgroupBackend.UDPTimeMode(),
			", udp_storage=", cgroupBackend.UDPStorageMode(),
			", self_bypass=", i.selfBypassMode(),
			", process_tracking=", i.processTrackingMode(),
		)
		return nil
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
				attachments = append(attachments, dataPlane.attachmentDescriptions()...)
			}
			if i.sharedRewrite != nil && i.sharedRewrite.dataPlane != nil {
				attachments = append(attachments, i.sharedRewrite.dataPlane.attachmentDescriptions()...)
			}
			return strings.Join(attachments, ", ")
		}(), "]",
		", listeners=[", i.listeners.String(), "]",
		", shared_rewrite_listeners=[", func() string {
			if i.sharedRewrite == nil {
				return ""
			}
			return i.sharedRewrite.listeners.String()
		}(), "]",
		", tcp_listener_lookup=", func() string {
			if backend == nil {
				return "none"
			}
			return backend.TCPListenerLookupMode()
		}(),
		", delivery_interface=", func() string {
			if dataPlane == nil {
				return ""
			}
			return dataPlane.deliveryName()
		}(),
		", routing_mark=", func() string {
			if dataPlane == nil {
				return ""
			}
			return "0x" + strconv.FormatUint(uint64(dataPlane.routing.mark), 16)
		}(),
		", routing_table=", func() string {
			if dataPlane == nil {
				return ""
			}
			return strconv.Itoa(dataPlane.routing.table)
		}(),
		", routing_priority=", func() string {
			if dataPlane == nil {
				return ""
			}
			return strconv.Itoa(dataPlane.routing.priority)
		}(),
		", self_bypass=", i.selfBypassMode(),
		", process_tracking=", i.processTrackingMode(),
		", tc_priority=", i.tcPriority,
	)
	return nil
}

func (i *Inbound) startProcessTracker() {
	if !i.localEnabled || !i.router.NeedFindProcess() || i.usePlatformProcessFinder || i.processTracker != nil {
		return
	}
	tracker, err := commonEBPF.AttachProcessTracker(commonEBPF.ProcessTrackerConfig{
		EnableTCP:   i.enableTCP,
		EnableUDP:   i.enableUDP,
		EnableIPv6:  i.localIPv6,
		LocalPolicy: i.localPolicy,
		MetadataMap: i.selfBypass.Map(),
	})
	if err != nil {
		i.logger.Debug("eBPF cgroup process tracking unavailable; using userspace process search: ", err)
		return
	}
	i.processTracker = tracker
}

func (i *Inbound) processTrackingMode() string {
	if i.usePlatformProcessFinder {
		return "platform"
	}
	if !i.localEnabled || !i.router.NeedFindProcess() {
		return "off"
	}
	if i.processTracker != nil {
		return "cgroup_socket"
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
		Mode:            mode,
		LocalDataPlane:  localPlane,
		SharedDataPlane: sharedPlane,
		Network:         network,
		InterfaceNames:  i.sharedOptions.Interface,
		EnableIPv6:      (localSelected && i.localIPv6) || (sharedSelected && i.sharedIPv6),
		NeedLPMPolicy: ((localTCEnabled || localCgroupEnabled) && (i.localPolicy.IncludeUIDConfigured || len(i.localPolicy.IncludeUID) > 0 || len(i.localPolicy.ExcludeUID) > 0)) ||
			((sharedSocketAssignEnabled || sharedRewriteEnabled) && (len(i.sharedOptions.IncludeSourceCIDR) > 0 || len(i.sharedOptions.ExcludeSourceCIDR) > 0)) ||
			len(i.bypassRuleSet) > 0,
		NeedProcessTracking: localSelected && i.router.NeedFindProcess() && !i.usePlatformProcessFinder,
	})
	if err != nil {
		return E.Cause(err, "probe eBPF kernel capabilities")
	}
	if err = report.RequiredError(); err != nil {
		return E.Cause(err, "probe eBPF kernel capabilities")
	}
	return nil
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
	if i.sharedRewrite != nil {
		sharedRewriteErr = i.sharedRewrite.Close()
		i.sharedRewrite = nil
	}
	dataPlane := i.takeTCDataPlane()
	disableErr := dataPlane.disable()
	cgroupBackend := i.takeCgroupBackend()
	cgroupErr := error(nil)
	if cgroupBackend != nil {
		cgroupErr = cgroupBackend.Close()
	}
	listenerErr := i.closeListeners()
	i.udpNat.Purge()
	udpReplySocketErr := i.udpReplySockets.close()
	dataPlaneErr := dataPlane.Close()
	routeErr := i.removeLocalRoutes()
	selfBypassErr := error(nil)
	if i.selfBypass != nil {
		if clearer, loaded := i.networkManager.(interface {
			ClearEBPFSelfBypass(*commonEBPF.SelfBypass)
		}); loaded {
			clearer.ClearEBPFSelfBypass(i.selfBypass)
		}
		selfBypassErr = i.selfBypass.Close()
		i.selfBypass = nil
	}
	processTrackerErr := error(nil)
	if i.processTracker != nil {
		processTrackerErr = i.processTracker.Close()
		i.processTracker = nil
	}
	return E.Errors(monitorErr, sharedRewriteErr, disableErr, listenerErr, udpReplySocketErr, dataPlaneErr, cgroupErr, routeErr, processTrackerErr, selfBypassErr)
}

func (i *Inbound) prepareCgroupBackend() error {
	backend, err := commonEBPF.PrepareCgroup(commonEBPF.CgroupConfig{
		Path:          i.cgroupPath,
		EnableTCP:     i.enableTCP,
		EnableUDP:     i.enableUDP,
		EnableIPv6:    i.cgroupIPv6Enabled(),
		RedirectIPv4:  i.redirectIPv4Prefix,
		RedirectIPv6:  i.redirectIPv6Prefix,
		MapCapacity:   commonEBPF.DefaultCgroupMapCapacity(),
		UDPTimeout:    i.udpTimeout,
		Policy:        i.compiledPolicy,
		SelfBypassMap: i.selfBypass.Map(),
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
	return i.tcDataPlane.backend
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

func (i *Inbound) setTCDataPlane(dataPlane *tcDataPlane) {
	i.tcDataPlaneAccess.Lock()
	i.tcDataPlane = dataPlane
	i.tcDataPlaneAccess.Unlock()
}

func (i *Inbound) takeTCDataPlane() *tcDataPlane {
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
	return i.tcDataPlane.reconcile(localInterface, sharedInterfaces, hostAddresses)
}
