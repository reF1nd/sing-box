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
		s.inbound.registerListenerSocket,
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
	return s.listeners.closeWithCleanup(s.inbound.unregisterListenerSockets)
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
