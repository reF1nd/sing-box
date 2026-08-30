//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"net/netip"
	"strings"
	"sync"
	"time"

	ECommon "github.com/sagernet/sing-box/common/ebpf"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	udpnat "github.com/sagernet/sing/common/udpnat2"
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
	sharedBackend        *ECommon.SharedNetworkBackend
	dataPlane            *sharedRewriteDataPlane
	listeners            internalListenerSet
	udpNat               *udpnat.Service
	sharedUDPClientTable sharedUDPClientTable
	udpWarnings          udpWarningLimiters
	tcpWarnings          warningLimiter
	mapCapacity          ECommon.SharedNetworkMapCapacities
	janitorWarnings      warningLimiter
	janitorAccess        sync.Mutex
	janitorCancel        context.CancelFunc
	janitorDone          chan struct{}
	tcPriority           uint16
	lifecycleAccess      sync.RWMutex
	backendAccess        sync.RWMutex
}

func newSharedRewrite(inbound *Inbound, options option.EBPFSharedOptions) *sharedRewrite {
	mapCapacity := effectiveSharedNetworkMapCapacity(
		ECommon.DefaultSharedNetworkMapCapacities(),
		len(inbound.bypassRuleSet) > 0 ||
			len(options.IncludeSourceCIDR) > 0 || len(options.ExcludeSourceCIDR) > 0 ||
			len(options.IncludeMACAddress) > 0 || len(options.ExcludeMACAddress) > 0,
	)
	shared := &sharedRewrite{
		inbound:     inbound,
		interfaces:  append([]string(nil), options.Interface...),
		mapCapacity: mapCapacity,
		tcPriority:  inbound.tcPriority,
	}
	shared.udpNat = udpnat.New(shared, shared.preparePacketConnection, inbound.udpTimeout, false)
	return shared
}

func effectiveSharedNetworkMapCapacity(
	capacity ECommon.SharedNetworkMapCapacities,
	bypassFlowCache bool,
) ECommon.SharedNetworkMapCapacities {
	if !bypassFlowCache {
		capacity.Bypass = 1
	}
	return capacity
}

func (s *sharedRewrite) Start(interfaceNames []string, hostAddresses []netip.Addr) error {
	if err := s.startListeners(); err != nil {
		return E.Errors(err, s.closeListeners())
	}
	s.dataPlane = newSharedRewriteDataPlane(s, s.tcPriority)
	if err := s.dataPlane.reconcile(interfaceNames, hostAddresses); err != nil {
		return E.Errors(err, s.Close())
	}
	if s.sharedBackendInstance() == nil {
		s.inbound.logger.Debug(
			"eBPF shared packet-rewrite waiting for downstream interfaces: interfaces=[",
			strings.Join(s.interfaces, ", "), "]",
		)
	}
	return nil
}

func (s *sharedRewrite) prepareBackend() (*ECommon.SharedNetworkBackend, error) {
	redirectIPv6 := netip.Prefix{}
	if s.inbound.sharedRewriteIPv6Enabled() {
		redirectIPv6 = s.inbound.redirectIPv6Prefix
	}
	cgroupBackend := s.inbound.cgroupBackendInstance()
	backend, err := ECommon.PrepareSharedNetwork(cgroupBackend, ECommon.SharedNetworkConfig{
		ListenerPort: s.listeners.selectedPort(),
		EnableTCP:    s.inbound.enableTCP,
		EnableUDP:    s.inbound.enableUDP,
		RedirectIPv4: s.inbound.redirectIPv4Prefix,
		RedirectIPv6: redirectIPv6,
		Policy:       s.inbound.compiledPolicy,
		MapCapacity:  s.mapCapacity,
		UDPTimeout:   s.inbound.udpTimeout,
	})
	if err != nil {
		return nil, err
	}
	s.inbound.bypassRuleSetAccess.Lock()
	if cgroupBackend != nil {
		ipv4Count, ipv6Count := cgroupBackend.BypassCIDRCount()
		err = backend.SetBypassCIDRState(ipv4Count, ipv6Count)
	} else {
		_, err = backend.UpdateCompiledBypassCIDR(s.inbound.bypassRuleSetPolicy)
	}
	if err == nil {
		s.setSharedBackend(backend)
	}
	s.inbound.bypassRuleSetAccess.Unlock()
	if err != nil {
		return nil, E.Errors(err, backend.Close())
	}
	return backend, nil
}

func (s *sharedRewrite) sharedRewriteReadyLocked(attachments []string) {
	s.startFlowJanitor()
	s.inbound.logger.Debug(
		"eBPF shared packet-rewrite active: attachments=[", strings.Join(attachments, ", "), "]",
		", redirect_listener_port=", s.listeners.selectedPort(),
		", dns_mode=", s.inbound.sharedDNSMode,
		", ipv6=", s.inbound.sharedRewriteIPv6Enabled(),
		", bypass_private_address=", s.inbound.sharedBypassPrivate,
		", source_cidr={include:", len(s.inbound.sharedOptions.IncludeSourceCIDR),
		", exclude:", len(s.inbound.sharedOptions.ExcludeSourceCIDR), "}",
		", source_mac={include:", len(s.inbound.sharedIncludeMAC),
		", exclude:", len(s.inbound.sharedExcludeMAC), "}",
	)
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
	var closeErr error
	if s.dataPlane != nil {
		closeErr = s.dataPlane.Close()
		s.dataPlane = nil
	}
	s.stopFlowJanitor()
	backend := s.takeSharedBackend()
	var backendErr error
	if backend != nil {
		backendErr = backend.Close()
		if !backend.IsClosed() {
			s.setSharedBackend(backend)
			if backendErr == nil {
				backendErr = E.New("shared-network eBPF backend remained open after close")
			}
		}
	}
	listenerErr := s.closeListeners()
	s.udpNat.Purge()
	return E.Errors(closeErr, backendErr, listenerErr)
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
	return s.dataPlane == nil && s.sharedBackendInstance() == nil && s.listeners.isClosed()
}

func (s *sharedRewrite) sharedBackendInstance() *ECommon.SharedNetworkBackend {
	s.backendAccess.RLock()
	defer s.backendAccess.RUnlock()
	return s.sharedBackend
}

func (s *sharedRewrite) takeSharedBackend() *ECommon.SharedNetworkBackend {
	s.backendAccess.Lock()
	backend := s.sharedBackend
	s.sharedBackend = nil
	s.backendAccess.Unlock()
	return backend
}

func (s *sharedRewrite) setSharedBackend(backend *ECommon.SharedNetworkBackend) {
	s.backendAccess.Lock()
	s.sharedBackend = backend
	s.backendAccess.Unlock()
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
	var releaseTimer *time.Timer
	var releaseTimerChannel <-chan time.Time
	resetReleaseTimer := func(backend *ECommon.SharedNetworkBackend) {
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
	belowExitRounds := 0
	var lastReservationFailures uint64
	scanInProgress := false
	for {
		backend := s.sharedBackendInstance()
		if backend == nil {
			return
		}
		sweepRequested := false
		select {
		case <-ctx.Done():
			return
		case <-backend.TCPFlowWake():
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
		case <-releaseTimerChannel:
		}
		now := time.Now()
		if !sweepRequested {
			_, flushErr := backend.FlushReleasedTCPFlows(now, sharedFlowReleaseFlushBudget)
			if flushErr != nil {
				s.janitorWarnings.warn(s.inbound.logger, "flush released shared-network TCP flows: ", flushErr)
			}
			resetReleaseTimer(backend)
			continue
		}
		if s.dataPlane == nil || !s.dataPlane.isEnabled() {
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
				backend.RequestMaintenance()
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
				s.inbound.logger.Warn(
					"eBPF shared-network proxy map pressure: state=", result.Usage.Entries,
					"/", result.Usage.Capacity,
					", max_idle=", sharedFlowPressureMaxIdle,
				)
			} else if exited {
				s.inbound.logger.Info(
					"eBPF shared-network proxy map pressure cleared: state=", result.Usage.Entries,
					"/", result.Usage.Capacity,
				)
			}
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
	if usage.Capacity == 0 {
		return false
	}
	if active {
		return uint64(usage.Entries)*100 > uint64(usage.Capacity)*sharedFlowPressureExitPercent
	}
	return uint64(usage.Entries)*100 >= uint64(usage.Capacity)*sharedFlowPressureEnterPercent
}

func updateSharedFlowPressure(active bool, belowExitRounds int, usage ECommon.MapUsage) (bool, int, bool, bool) {
	if usage.Capacity == 0 {
		return active, 0, false, false
	}
	if !active {
		if uint64(usage.Entries)*100 >= uint64(usage.Capacity)*sharedFlowPressureEnterPercent {
			return true, 0, true, false
		}
		return false, 0, false, false
	}
	if uint64(usage.Entries)*100 > uint64(usage.Capacity)*sharedFlowPressureExitPercent {
		return true, 0, false, false
	}
	belowExitRounds++
	if belowExitRounds < sharedFlowPressureExitRounds {
		return true, belowExitRounds, false, false
	}
	return false, 0, false, true
}
