//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
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
	sharedFlowSweepInterval        = 5 * time.Minute
	sharedFlowPressureInterval     = 5 * time.Second
	sharedFlowPressureEnterPercent = 70
	sharedFlowPressureExitPercent  = 50
	sharedFlowPressureExitRounds   = 3
	sharedFlowFallbackScanBudget   = 1024
	sharedFlowReleaseFlushBudget   = 4096
)

type sharedNetwork struct {
	inbound         *Inbound
	interfaces      []string
	sharedBackend   *ECommon.SharedNetworkBackend
	tcManager       *sharedTCManager
	listeners       internalListenerSet
	udpNat          *udpnat.Service
	udpClientTable  udpClientTable
	udpWarnings     udpWarningLimiters
	tcpWarnings     warningLimiter
	mapCapacity     ECommon.SharedNetworkMapCapacities
	janitorWarnings warningLimiter
	janitorAccess   sync.Mutex
	janitorCancel   context.CancelFunc
	janitorDone     chan struct{}
	tcPriority      uint16
	lifecycleAccess sync.RWMutex
	backendAccess   sync.RWMutex
}

func newSharedNetwork(inbound *Inbound, options option.EBPFSharedOptions) *sharedNetwork {
	tcPriority := uint16(options.Advanced.TCPriority)
	if tcPriority == 0 {
		tcPriority = defaultSharedNetworkTCPriority
	}
	mapCapacity := effectiveSharedNetworkMapCapacity(
		inbound.sharedNetworkMapCapacity,
		len(inbound.bypassRuleSet) > 0 ||
			len(options.IncludeSourceCIDR) > 0 || len(options.ExcludeSourceCIDR) > 0 ||
			len(options.IncludeMACAddress) > 0 || len(options.ExcludeMACAddress) > 0,
	)
	shared := &sharedNetwork{
		inbound:     inbound,
		interfaces:  append([]string(nil), options.Interface...),
		mapCapacity: mapCapacity,
		tcPriority:  tcPriority,
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

func (s *sharedNetwork) Start(cgroupBackend *ECommon.CgroupBackend) error {
	if err := s.startListeners(); err != nil {
		return E.Errors(err, s.closeListeners())
	}
	s.tcManager = &sharedTCManager{
		prepareBackend: func() (*ECommon.SharedNetworkBackend, error) {
			return s.prepareBackend(cgroupBackend)
		},
		onReady:        s.sharedNetworkReady,
		logger:         s.inbound.logger,
		interfaces:     s.interfaces,
		enableIPv4:     s.inbound.redirectIPv4Prefix.IsValid(),
		priority:       s.tcPriority,
		networkMonitor: s.inbound.networkManager.NetworkMonitor(),
		attachments:    make(map[string]*sharedTCAttachment),
	}
	if err := s.tcManager.Start(); err != nil {
		return E.Errors(err, s.Close())
	}
	if s.sharedBackendInstance() == nil {
		s.inbound.logger.Info(
			"eBPF shared-network waiting for downstream interfaces before loading programs: interfaces=[",
			strings.Join(s.interfaces, ", "), "]",
		)
	}
	return nil
}

func (s *sharedNetwork) prepareBackend(cgroupBackend *ECommon.CgroupBackend) (*ECommon.SharedNetworkBackend, error) {
	backend, err := ECommon.PrepareSharedNetwork(cgroupBackend, ECommon.SharedNetworkConfig{
		ListenerPort:         s.listeners.selectedPort(),
		EnableTCP:            s.inbound.enableTCP,
		EnableUDP:            s.inbound.enableUDP,
		DNSMode:              commonDNSMode(s.inbound.sharedDNSMode),
		BypassPrivateAddress: s.inbound.sharedBypassPrivateAddress,
		RedirectIPv4:         s.inbound.redirectIPv4Prefix,
		RedirectIPv6:         s.inbound.sharedRedirectIPv6Prefix(),
		FakeIPIPv4:           s.inbound.fakeIPIPv4Prefix,
		FakeIPIPv6:           s.inbound.fakeIPIPv6Prefix,
		IncludeSourceCIDR:    s.inbound.sharedNetworkOptions.IncludeSourceCIDR,
		ExcludeSourceCIDR:    s.inbound.sharedNetworkOptions.ExcludeSourceCIDR,
		IncludeSourceMAC:     s.inbound.sharedNetworkIncludeMAC,
		ExcludeSourceMAC:     s.inbound.sharedNetworkExcludeMAC,
		MapCapacity:          s.mapCapacity,
		UDPTimeout:           s.inbound.udpTimeout,
	})
	if err != nil {
		return nil, err
	}
	if cgroupBackend == nil {
		s.inbound.bypassRuleSetAccess.Lock()
		policy := s.inbound.bypassRuleSetPolicy
		_, err = backend.UpdateCompiledBypassCIDR(policy)
		if err != nil {
			s.inbound.bypassRuleSetAccess.Unlock()
			closeErr := backend.Close()
			return nil, E.Errors(err, closeErr)
		}
		s.inbound.bypassRuleSetDirty = false
		s.setSharedBackend(backend)
		s.inbound.bypassRuleSetAccess.Unlock()
	} else {
		ipv4Count, ipv6Count := cgroupBackend.BypassCIDRCount()
		if err = backend.SetBypassCIDRState(ipv4Count, ipv6Count); err != nil {
			closeErr := backend.Close()
			return nil, E.Errors(err, closeErr)
		}
		s.setSharedBackend(backend)
	}
	return backend, nil
}

func (s *sharedNetwork) sharedNetworkReady() {
	s.startFlowJanitor()
	bypassMapSource := "local_cgroup"
	if s.inbound.cgroupBackendInstance() == nil {
		bypassMapSource = "standalone"
	}
	s.inbound.logger.Info(
		"eBPF shared-network TC interception ready: downstream_interfaces=[", s.tcManager.InterfaceString(),
		"], attachment_mode=", s.tcManager.AttachmentModeString(),
		", redirect_listener_port=", s.listeners.selectedPort(),
		", dns_mode=", s.inbound.sharedDNSMode,
		", ipv6=", s.inbound.sharedNetworkIPv6Enabled(),
		", bypass_maps=", bypassMapSource,
		", bypass_private_address=", s.inbound.sharedBypassPrivateAddress,
		", source_cidr={include:", len(s.inbound.sharedNetworkOptions.IncludeSourceCIDR),
		", exclude:", len(s.inbound.sharedNetworkOptions.ExcludeSourceCIDR), "}",
		", source_mac={include:", len(s.inbound.sharedNetworkIncludeMAC),
		", exclude:", len(s.inbound.sharedNetworkExcludeMAC), "}",
	)
	s.inbound.logDebugSharedDetails(s)
}

func (s *sharedNetwork) startListeners() error {
	return s.listeners.start(
		s.inbound.enableTCP,
		s.inbound.enableUDP,
		s.inbound.redirectIPv4Prefix.IsValid(),
		s.inbound.sharedNetworkIPv6Enabled(),
		s.newListener,
	)
}

func (s *sharedNetwork) newListener(network string, ipv6Listener bool, port uint16) *listener.Listener {
	return s.inbound.newInternalListener(s, network, ipv6Listener, port)
}

func (s *sharedNetwork) InterfaceUpdated() {
	s.lifecycleAccess.RLock()
	defer s.lifecycleAccess.RUnlock()
	s.udpNat.Purge()
	if manager := s.tcManager; manager != nil {
		manager.Wake()
	}
}

func (s *sharedNetwork) Close() error {
	if s == nil {
		return nil
	}
	s.lifecycleAccess.Lock()
	defer s.lifecycleAccess.Unlock()
	var closeErr error
	if s.tcManager != nil {
		closeErr = s.tcManager.Close()
		s.tcManager = nil
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

func (s *sharedNetwork) closeListeners() error {
	return s.listeners.close()
}

func (s *sharedNetwork) IsClosed() bool {
	if s == nil {
		return true
	}
	s.lifecycleAccess.RLock()
	defer s.lifecycleAccess.RUnlock()
	return s.tcManager == nil && s.sharedBackendInstance() == nil && s.listeners.isClosed()
}

func (s *sharedNetwork) sharedBackendInstance() *ECommon.SharedNetworkBackend {
	s.backendAccess.RLock()
	defer s.backendAccess.RUnlock()
	return s.sharedBackend
}

func (s *sharedNetwork) takeSharedBackend() *ECommon.SharedNetworkBackend {
	s.backendAccess.Lock()
	backend := s.sharedBackend
	s.sharedBackend = nil
	s.backendAccess.Unlock()
	return backend
}

func (s *sharedNetwork) setSharedBackend(backend *ECommon.SharedNetworkBackend) {
	s.backendAccess.Lock()
	s.sharedBackend = backend
	s.backendAccess.Unlock()
}

func (s *sharedNetwork) startFlowJanitor() {
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

func (s *sharedNetwork) stopFlowJanitor() {
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

func (s *sharedNetwork) runFlowJanitor(ctx context.Context, done chan<- struct{}) {
	defer close(done)
	pressureTicker := time.NewTicker(sharedFlowPressureInterval)
	defer pressureTicker.Stop()
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
	belowExitRounds := 0
	lastSweep := time.Now()
	var lastReservationFailures uint64
	scanInProgress := false
	attachmentActive := s.tcManager != nil && s.tcManager.isEnabled()
	for {
		backend := s.sharedBackendInstance()
		if backend == nil {
			return
		}
		pressurePoll := false
		select {
		case <-ctx.Done():
			return
		case <-pressureTicker.C:
			pressurePoll = true
		case <-backend.TCPFlowReleaseWake():
			resetReleaseTimer(backend)
			continue
		case <-releaseTimerChannel:
		}
		now := time.Now()
		if !pressurePoll {
			_, flushErr := backend.FlushReleasedTCPFlows(now, sharedFlowReleaseFlushBudget)
			if flushErr != nil {
				s.janitorWarnings.warn(s.inbound.logger, "flush released shared-network TCP flows: ", flushErr)
			}
			resetReleaseTimer(backend)
			continue
		}
		if s.tcManager == nil || !s.tcManager.isEnabled() {
			attachmentActive = false
			pressure = false
			belowExitRounds = 0
			scanInProgress = false
			continue
		}
		if !attachmentActive {
			attachmentActive = true
			lastSweep = time.Time{}
		}
		reservationPressure := false
		reservationFailures, failureErr := backend.TokenReservationFailures()
		if failureErr != nil {
			s.janitorWarnings.warn(s.inbound.logger, "read shared-network token reservation failures: ", failureErr)
		} else {
			reservationPressure = reservationFailures > lastReservationFailures
			lastReservationFailures = reservationFailures
		}
		if !sharedFlowSweepRequired(now.Sub(lastSweep), pressure, reservationPressure, scanInProgress) {
			continue
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
			if result.Complete {
				lastSweep = now
			}
			s.inbound.logDebugSharedFlowCleanup(result)
			if !result.Complete {
				continue
			}
			entered, exited := false, false
			pressure, belowExitRounds, entered, exited = updateSharedFlowPressure(
				pressure,
				belowExitRounds,
				result.Usage,
			)
			if entered {
				s.inbound.logger.Warn(
					"eBPF shared-network proxy map pressure: state=", result.Usage.Entries,
					"/", result.Usage.Capacity,
					", sweep_interval=", sharedFlowPressureInterval,
					", max_idle=", sharedFlowPressureMaxIdle,
				)
			} else if exited {
				s.inbound.logger.Info(
					"eBPF shared-network proxy map pressure cleared: state=", result.Usage.Entries,
					"/", result.Usage.Capacity,
					", sweep_interval=", sharedFlowSweepInterval,
				)
			}
		}
	}
}

func sharedFlowSweepRequired(
	elapsed time.Duration,
	pressure bool,
	reservationPressure bool,
	scanInProgress bool,
) bool {
	return pressure || reservationPressure || scanInProgress || elapsed >= sharedFlowSweepInterval
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
