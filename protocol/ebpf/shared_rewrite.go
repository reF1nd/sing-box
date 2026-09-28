//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"net/netip"
	"runtime"
	"sync"
	"time"

	ECommon "github.com/CHIZI-0618/sing-ebpf"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

const (
	sharedFlowMaxIdle              = 5 * time.Minute
	sharedFlowPressureMaxIdle      = 15 * time.Second
	sharedFlowPressureEnterPercent = 70
	sharedFlowPressureExitPercent  = 50
	sharedFlowPressureExitRounds   = 3
	sharedFlowFallbackScanBudget   = 1024
	sharedFlowReleaseFlushBudget   = 4096
)

type sharedRewrite struct {
	inbound              *Inbound
	interfaces           []string
	dataPlane            sharedKernelRuntime
	listeners            internalListenerSet
	udpNat               *udpNATService
	sharedUDPClientTable sharedUDPClientTable
	udpWarnings          udpWarningLimiters
	tcpWarnings          warningLimiter
	mapCapacity          ECommon.SharedPacketRewriteMapCapacity
	janitorWarnings      warningLimiter
	janitorAccess        sync.Mutex
	janitorCancel        context.CancelFunc
	janitorDone          chan struct{}
	tcPriority           uint16
	lifecycleAccess      sync.RWMutex
	dataPlaneAccess      sync.RWMutex
}

func newSharedRewrite(inbound *Inbound, options option.EBPFSharedOptions) *sharedRewrite {
	defaultMapCapacity := ECommon.DefaultSharedPacketRewriteMapCapacity()
	if runtime.GOOS == "android" {
		defaultMapCapacity = ECommon.CompactSharedPacketRewriteMapCapacity()
	}
	mapCapacity := effectiveSharedPacketRewriteMapCapacity(
		defaultMapCapacity,
		len(inbound.sharedBypassRules.ruleSets) > 0 ||
			len(options.IncludeSourceCIDR) > 0 || len(options.ExcludeSourceCIDR) > 0 ||
			len(options.IncludeMACAddress) > 0 || len(options.ExcludeMACAddress) > 0,
	)
	shared := &sharedRewrite{
		inbound:     inbound,
		interfaces:  append([]string(nil), options.Interface...),
		mapCapacity: mapCapacity,
		tcPriority:  inbound.tcPriority,
	}
	if inbound.enableUDP {
		shared.udpNat = newUDPNATService(shared, shared.preparePacketConnection, inbound.udpTimeout)
	}
	return shared
}

func effectiveSharedPacketRewriteMapCapacity(
	capacity ECommon.SharedPacketRewriteMapCapacity,
	bypassFlowCache bool,
) ECommon.SharedPacketRewriteMapCapacity {
	if !bypassFlowCache {
		capacity.Bypass = 1
	}
	return capacity
}

func (s *sharedRewrite) Start(interfaceNames []string, hostAddresses []netip.Addr) error {
	if err := s.startListeners(); err != nil {
		return E.Errors(err, s.closeListeners())
	}
	dataPlane := newSharedKernelRuntime(s.kernelRuntimeHooks(), s.tcPriority)
	s.setDataPlane(dataPlane)
	if err := dataPlane.Reconcile(interfaceNames, hostAddresses); err != nil {
		return E.Errors(err, s.Close())
	}
	s.startFlowJanitor()
	if s.sharedBackendInstance() == nil {
		s.inbound.logger.Debug("eBPF ", ebpfStructuredEvent("shared_waiting", map[string]any{
			"interfaces": s.interfaces,
		}))
	}
	return nil
}

func (s *sharedRewrite) prepareBackend() (*ECommon.SharedPacketRewriteBackend, error) {
	redirectIPv6 := netip.Prefix{}
	if s.inbound.sharedRewriteIPv6Enabled() {
		redirectIPv6 = s.inbound.redirectIPv6Prefix
	}
	backend, err := ECommon.PrepareSharedPacketRewrite(ECommon.SharedPacketRewriteConfig{
		ListenerPort:  s.listeners.selectedPort(),
		EnableTCP:     s.inbound.enableTCP,
		EnableUDP:     s.inbound.enableUDP,
		RedirectIPv4:  s.inbound.redirectIPv4Prefix,
		RedirectIPv6:  redirectIPv6,
		Policy:        s.inbound.compiledPolicy,
		MapCapacity:   s.mapCapacity,
		UDPTimeout:    s.inbound.udpTimeout,
		ICMPEchoReply: s.inbound.fakeIPICMPReply,
	})
	if err != nil {
		return nil, err
	}
	s.inbound.bypassRuleSetAccess.Lock()
	initialPolicy, policyErr := s.inbound.combineDestinationDecisions(
		s.inbound.sharedInitialDestinations,
		s.inbound.sharedBypassRules.policy,
	)
	if policyErr == nil {
		_, err = backend.UpdateDestinationDecisions(initialPolicy)
	} else {
		err = policyErr
	}
	s.inbound.bypassRuleSetAccess.Unlock()
	if err != nil {
		return nil, E.Errors(err, backend.Close())
	}
	return backend, nil
}

func (s *sharedRewrite) sharedRewriteReady(attachments []string) {
	s.lifecycleAccess.RLock()
	defer s.lifecycleAccess.RUnlock()
	dataPlane := s.dataPlaneInstance()
	if dataPlane == nil || !dataPlane.IsEnabled() {
		return
	}
	s.startFlowJanitor()
	s.inbound.logger.Debug("eBPF ", ebpfStructuredEvent("shared_active", map[string]any{
		"attachments":            attachments,
		"default_interface":      s.inbound.sharedOptions.DefaultInterface,
		"listener_port":          s.listeners.selectedPort(),
		"dns_mode":               s.inbound.sharedDNSMode,
		"ipv6":                   s.inbound.sharedRewriteIPv6Enabled(),
		"bypass_private_address": s.inbound.sharedBypassPrivate,
		"source_cidr_include":    len(s.inbound.sharedOptions.IncludeSourceCIDR),
		"source_cidr_exclude":    len(s.inbound.sharedOptions.ExcludeSourceCIDR),
		"source_mac_include":     len(s.inbound.sharedIncludeMAC),
		"source_mac_exclude":     len(s.inbound.sharedExcludeMAC),
	}))
}

func (s *sharedRewrite) startListeners() error {
	return s.listeners.start(
		s.inbound.enableTCP,
		s.inbound.enableUDP,
		s.inbound.redirectIPv4Prefix.IsValid(),
		s.inbound.sharedRewriteIPv6Enabled(),
		s.newListener,
	)
}

func (s *sharedRewrite) newListener(network string, ipv6Listener bool, port uint16) *listener.Listener {
	return s.inbound.newInternalListener(s, network, ipv6Listener, port)
}

func (s *sharedRewrite) Close() error {
	if s == nil {
		return nil
	}
	s.lifecycleAccess.Lock()
	defer s.lifecycleAccess.Unlock()
	s.stopFlowJanitor()
	var closeErr error
	if dataPlane := s.takeDataPlane(); dataPlane != nil {
		closeErr = dataPlane.Close()
		if !dataPlane.IsClosed() {
			s.setDataPlane(dataPlane)
			if closeErr == nil {
				closeErr = E.New("shared packet-rewrite runtime remained open after close")
			}
			return closeErr
		}
	}
	listenerErr := s.closeListeners()
	udpNATErr := s.udpNat.Close()
	return E.Errors(closeErr, listenerErr, udpNATErr)
}

func (s *sharedRewrite) closeListeners() error {
	return s.listeners.close()
}

func (s *sharedRewrite) IsClosed() bool {
	if s == nil {
		return true
	}
	s.lifecycleAccess.RLock()
	defer s.lifecycleAccess.RUnlock()
	return s.dataPlaneInstance() == nil && s.listeners.isClosed()
}

// dataPlaneInstance, setDataPlane, and takeDataPlane guard s.dataPlane:
// Diagnostics, the interface-monitor update loop, and the flow janitor
// goroutine all read this field with no relationship to Close's own
// lifecycleAccess lock. The returned interface must be checked for nil before
// use; concrete implementations may not support nil receivers after this
// runtime moves.
func (s *sharedRewrite) dataPlaneInstance() sharedKernelRuntime {
	s.dataPlaneAccess.RLock()
	defer s.dataPlaneAccess.RUnlock()
	return s.dataPlane
}

func (s *sharedRewrite) setDataPlane(dataPlane sharedKernelRuntime) {
	s.dataPlaneAccess.Lock()
	s.dataPlane = dataPlane
	s.dataPlaneAccess.Unlock()
}

func (s *sharedRewrite) takeDataPlane() sharedKernelRuntime {
	s.dataPlaneAccess.Lock()
	dataPlane := s.dataPlane
	s.dataPlane = nil
	s.dataPlaneAccess.Unlock()
	return dataPlane
}

func (s *sharedRewrite) sharedBackendInstance() *ECommon.SharedPacketRewriteBackend {
	dataPlane := s.dataPlaneInstance()
	if dataPlane == nil {
		return nil
	}
	return dataPlane.Backend()
}

func (s *sharedRewrite) startFlowJanitor() {
	s.janitorAccess.Lock()
	defer s.janitorAccess.Unlock()
	if s.janitorCancel != nil {
		return
	}
	ctx, cancel := context.WithCancel(s.inbound.ctx)
	done := make(chan struct{})
	s.janitorCancel = cancel
	s.janitorDone = done
	go s.runFlowJanitor(ctx, done)
}

func (s *sharedRewrite) stopFlowJanitor() {
	s.janitorAccess.Lock()
	if s.janitorCancel == nil {
		s.janitorAccess.Unlock()
		return
	}
	cancel := s.janitorCancel
	done := s.janitorDone
	s.janitorCancel = nil
	s.janitorDone = nil
	s.janitorAccess.Unlock()
	cancel()
	<-done
}

func (s *sharedRewrite) runFlowJanitor(ctx context.Context, done chan<- struct{}) {
	defer close(done)
	tcTicker := time.NewTicker(tcAssignmentMaintenanceInterval)
	defer tcTicker.Stop()
	var tcContinuation <-chan time.Time
	var tcTimer *time.Timer
	var tcSchedule maintenanceSchedule
	// Independent jobs share scheduling semantics, never one another's state.
	var flowSchedule maintenanceSchedule
	var flowTimer *time.Timer
	var flowContinuation <-chan time.Time
	defer func() {
		if tcTimer != nil {
			tcTimer.Stop()
		}
		if flowTimer != nil {
			flowTimer.Stop()
		}
	}()
	tcMaintenancePending := false
	var releaseTimer *time.Timer
	var releaseTimerChannel <-chan time.Time
	resetReleaseTimer := func(backend *ECommon.SharedPacketRewriteBackend) {
		delay, available := backend.NextTCPFlowReleaseDelay(time.Now())
		if !available {
			if releaseTimer != nil {
				releaseTimer.Stop()
			}
			releaseTimerChannel = nil
			return
		}
		if releaseTimer == nil {
			releaseTimer = time.NewTimer(delay)
		} else {
			if !releaseTimer.Stop() {
				select {
				case <-releaseTimer.C:
				default:
				}
			}
			releaseTimer.Reset(delay)
		}
		releaseTimerChannel = releaseTimer.C
	}
	defer func() {
		if releaseTimer != nil {
			releaseTimer.Stop()
		}
	}()
	pressure := false
	knownPressure := false
	var belowExitRounds uint32
	var lastReservationFailures uint64
	scanInProgress := false
	for {
		backend := s.sharedBackendInstance()
		var flowWake <-chan struct{}
		if backend != nil {
			flowWake = backend.TCPFlowWake()
		}
		var tcWake <-chan struct{}
		if tcContinuation == nil {
			tcWake = s.inbound.tcAssignmentWake
		}
		sweepRequested := false
		select {
		case <-ctx.Done():
			return
		case <-flowWake:
			resetReleaseTimer(backend)
			knownPressure, sweepRequested = updateSharedFlowWakeState(
				pressure,
				knownPressure,
				scanInProgress,
				backend.KnownFlowUsage(),
			)
			if !sweepRequested {
				continue
			}
		case <-tcWake:
			tcMaintenancePending = true
		case <-tcTicker.C:
			tcMaintenancePending = true
			// Kernel-only allocations do not appear in KnownFlowUsage and may
			// never produce a userspace wake. Keep a bounded orphan watchdog.
			sweepRequested = flowContinuation == nil
		case <-tcContinuation:
			tcContinuation = nil
			tcMaintenancePending = true
		case <-releaseTimerChannel:
		case <-flowContinuation:
			flowContinuation = nil
			sweepRequested = true
		}
		if tcMaintenancePending {
			s.inbound.maintainTCAssignments(&tcSchedule, &tcTimer, &tcContinuation)
			tcMaintenancePending = false
		}
		if backend == nil {
			continue
		}
		now := time.Now()
		if sweepRequested {
			if delay := flowSchedule.delay(now); delay > 0 {
				if flowContinuation == nil {
					resetMaintenanceTimer(&flowTimer, &flowContinuation, delay)
				}
				sweepRequested = false
			}
		}
		if !sweepRequested {
			_, flushErr := backend.FlushReleasedTCPFlows(now, sharedFlowReleaseFlushBudget)
			if flushErr != nil {
				s.janitorWarnings.warn(s.inbound.logger, "flush released shared-network TCP flows: ", flushErr)
			}
			resetReleaseTimer(backend)
			continue
		}
		dataPlane := s.dataPlaneInstance()
		if dataPlane == nil || !dataPlane.IsEnabled() {
			pressure = false
			knownPressure = false
			belowExitRounds = 0
			scanInProgress = false
			continue
		}
		reservationPressure := false
		reservationFailures, failureErr := backend.TokenReservationFailures()
		if failureErr != nil {
			s.janitorWarnings.warn(s.inbound.logger, "read shared-network token reservation failures: ", failureErr)
		} else {
			reservationPressure = reservationFailures > lastReservationFailures
			lastReservationFailures = reservationFailures
		}
		maxIdle := sharedFlowMaxIdle
		if pressure || reservationPressure {
			maxIdle = sharedFlowPressureMaxIdle
		}
		result, err := backend.SweepOrphanedFlows(maxIdle, sharedFlowFallbackScanBudget)
		if err != nil {
			if reservationPressure {
				pressure = true
			}
			s.janitorWarnings.warn(s.inbound.logger, "sweep orphaned shared-network flows: ", err)
		} else {
			scanInProgress = !result.Complete
			if !result.Complete {
				resetMaintenanceTimer(&flowTimer, &flowContinuation, flowSchedule.finish(time.Now(), false, pressure, nil))
				continue
			}
			entered, exited := false, false
			pressure, belowExitRounds, entered, exited = updateSharedFlowPressure(
				pressure,
				belowExitRounds,
				result.Usage,
			)
			if reservationPressure {
				pressure = true
				belowExitRounds = 0
			}
			if entered {
				s.inbound.logger.Warn("eBPF ", ebpfStructuredEvent("shared_map_pressure", map[string]any{
					"entries":  result.Usage.Entries,
					"capacity": result.Usage.Capacity,
					"max_idle": sharedFlowPressureMaxIdle.String(),
				}))
			} else if exited {
				s.inbound.logger.Info("eBPF ", ebpfStructuredEvent("shared_map_pressure_cleared", map[string]any{
					"entries":  result.Usage.Entries,
					"capacity": result.Usage.Capacity,
				}))
			}
		}
		if delay := flowSchedule.finish(time.Now(), result.Complete, pressure, err); delay > 0 {
			resetMaintenanceTimer(&flowTimer, &flowContinuation, delay)
		}
	}
}

func updateSharedFlowWakeState(pressure, knownPressure, scanInProgress bool, usage ECommon.MapUsage) (bool, bool) {
	if !knownPressure {
		knownPressure = flowUsagePressure(false, usage)
	} else if !flowUsagePressure(true, usage) {
		knownPressure = false
	}
	return knownPressure, pressure || knownPressure || scanInProgress
}

func flowUsagePressure(active bool, usage ECommon.MapUsage) bool {
	if active {
		return mapUsageAbovePercent(usage, sharedFlowPressureExitPercent)
	}
	return mapUsageAtLeastPercent(usage, sharedFlowPressureEnterPercent)
}

func updateSharedFlowPressure(active bool, belowExitRounds uint32, usage ECommon.MapUsage) (bool, uint32, bool, bool) {
	return updateMapPressure(active, belowExitRounds, usage, mapPressureHysteresis{
		enterPercent: sharedFlowPressureEnterPercent,
		exitPercent:  sharedFlowPressureExitPercent,
		exitRounds:   sharedFlowPressureExitRounds,
	})
}
