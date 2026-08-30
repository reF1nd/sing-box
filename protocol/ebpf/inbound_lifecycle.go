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
	if err := i.startTCInbound(); err != nil {
		return combineStartError(err, i.cleanupStartFailure())
	}
	return nil
}

func (i *Inbound) startTCInbound() error {
	if i.localEnabled && i.androidUIDOptions != nil {
		if err := i.resolveAndroidUIDPolicy(); err != nil {
			return E.Cause(err, "resolve Android UID policy")
		}
	}
	if err := i.checkKernelCapabilities(); err != nil {
		return err
	}
	i.startProcessTracker()
	defaultInterface := i.currentDefaultInterfaceName()
	localInterface := ""
	if i.localEnabled {
		localInterface = defaultInterface
		if localInterface == "" {
			i.logger.Warn("default interface unavailable; local TC eBPF interception is paused")
		}
	}
	sharedInterfaces := activeSharedInterfaces(i.sharedOptions.Interface, defaultInterface)
	if err := i.startTCListeners(); err != nil {
		return err
	}
	backendConfig := commonEBPF.TCConfig{
		ListenerPort:        i.listeners.selectedPort(),
		EnableLocal:         i.localEnabled,
		EnableShared:        i.sharedEnabled,
		EnableIPv4:          true,
		EnableLocalIPv6:     i.localIPv6,
		EnableSharedIPv6:    i.sharedIPv6,
		EnableTCP:           i.enableTCP,
		EnableUDP:           i.enableUDP,
		LocalPolicy:         i.localPolicy,
		SharedDNSMode:       toCommonDNSMode(i.sharedDNSMode),
		SharedBypassPrivate: i.sharedBypassPrivate,
		FakeIPIPv4:          i.fakeIPIPv4Prefix,
		FakeIPIPv6:          i.fakeIPIPv6Prefix,
		IncludeSourceCIDR:   i.sharedOptions.IncludeSourceCIDR,
		ExcludeSourceCIDR:   i.sharedOptions.ExcludeSourceCIDR,
		IncludeSourceMAC:    i.sharedIncludeMAC,
		ExcludeSourceMAC:    i.sharedExcludeMAC,
		SelfBypassMap:       i.selfBypass.Map(),
		LocalBypassPort:     i.localBypassPort,
		SharedBypassPort:    i.sharedBypassPort,
		TrackProcess:        i.processTracker != nil,
	}
	backend, err := commonEBPF.PrepareTC(backendConfig)
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
	if err = i.listeners.registerTCTCPListeners(backend); err != nil {
		return E.Errors(err, backend.Close())
	}
	dataPlane, err := startTCDataPlane(
		backend,
		i.localEnabled,
		i.localIPv6 || i.sharedIPv6,
		localInterface,
		sharedInterfaces,
		i.hostAddresses(),
		len(i.sharedIncludeMAC)+len(i.sharedExcludeMAC) > 0,
		i.tcPriority,
	)
	if err != nil {
		return err
	}
	i.setTCDataPlane(dataPlane)
	if err = i.startBypassRuleSets(); err != nil {
		return E.Cause(err, "initialize TC eBPF bypass_rule_set")
	}
	if err = backend.Enable(); err != nil {
		return err
	}
	if err = i.startTCInterfaceMonitor(); err != nil {
		return err
	}
	network := "tcp"
	if i.enableTCP && i.enableUDP {
		network = "tcp,udp"
	} else if i.enableUDP {
		network = "udp"
	}
	i.logger.Debug(
		"eBPF TC active: mode=", i.mode,
		", network=", network,
		", local_ipv6=", i.localIPv6,
		", shared_ipv6=", i.sharedIPv6,
		", default_interface=", defaultInterface,
		", local_interface=", localInterface,
		", shared_interfaces=[", strings.Join(i.sharedOptions.Interface, ", "), "]",
		", attachments=[", strings.Join(dataPlane.attachmentDescriptions(), ", "), "]",
		", listeners=[", i.listeners.String(), "]",
		", tcp_listener_lookup=", backend.TCPListenerLookupMode(),
		", delivery_interface=", dataPlane.deliveryName(),
		", routing_mark=0x", strconv.FormatUint(uint64(dataPlane.routing.mark), 16),
		", routing_table=", dataPlane.routing.table,
		", routing_priority=", dataPlane.routing.priority,
		", self_bypass=", func() string {
			if !i.localEnabled {
				return "none"
			}
			if i.selfBypassCgroup {
				return i.selfBypass.Mode().String()
			}
			return "userspace_socket_cookie"
		}(),
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
	mode := commonEBPF.KernelProbeModeShared
	if i.localEnabled && i.sharedEnabled {
		mode = commonEBPF.KernelProbeModeAll
	} else if i.localEnabled {
		mode = commonEBPF.KernelProbeModeLocal
	}
	network := make([]string, 0, 2)
	if i.enableTCP {
		network = append(network, "tcp")
	}
	if i.enableUDP {
		network = append(network, "udp")
	}
	interfaceName := ""
	if len(i.sharedOptions.Interface) > 0 {
		interfaceName = i.sharedOptions.Interface[0]
	}
	report, err := commonEBPF.ProbeKernel(commonEBPF.KernelProbeOptions{
		Mode:                mode,
		Network:             network,
		InterfaceName:       interfaceName,
		EnableIPv6:          i.localIPv6 || i.sharedIPv6,
		NeedProcessTracking: i.localEnabled && i.router.NeedFindProcess() && !i.usePlatformProcessFinder,
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
	dataPlane := i.takeTCDataPlane()
	disableErr := dataPlane.disable()
	listenerErr := i.closeListeners()
	i.udpNat.Purge()
	udpReplySocketErr := i.udpReplySockets.close()
	dataPlaneErr := dataPlane.Close()
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
	return E.Errors(monitorErr, disableErr, listenerErr, udpReplySocketErr, dataPlaneErr, processTrackerErr, selfBypassErr)
}

func (i *Inbound) tcBackend() *commonEBPF.TCBackend {
	i.tcDataPlaneAccess.RLock()
	defer i.tcDataPlaneAccess.RUnlock()
	if i.tcDataPlane == nil {
		return nil
	}
	return i.tcDataPlane.backend
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
