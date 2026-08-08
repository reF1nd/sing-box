//go:build with_ebpf && (linux || android)

package ebpf

import (
	"sync"

	ECommon "github.com/sagernet/sing-box/common/ebpf"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	udpnat "github.com/sagernet/sing/common/udpnat2"
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
	mapCapacity     ECommon.SharedNetworkMapCapacities
	tcPriority      uint16
	lifecycleAccess sync.RWMutex
	backendAccess   sync.RWMutex
}

func newSharedNetwork(inbound *Inbound, options option.EBPFSharedNetworkOptions) *sharedNetwork {
	tcPriority := uint16(options.TCPriority)
	if tcPriority == 0 {
		tcPriority = defaultSharedNetworkTCPriority
	}
	shared := &sharedNetwork{
		inbound:     inbound,
		interfaces:  append([]string(nil), options.IncludeInterface...),
		mapCapacity: inbound.sharedNetworkMapCapacity,
		tcPriority:  tcPriority,
	}
	shared.udpNat = udpnat.New(shared, shared.preparePacketConnection, inbound.udpTimeout, false)
	return shared
}

func (s *sharedNetwork) Start(cgroupBackend *ECommon.CgroupBackend) error {
	if err := s.startListeners(); err != nil {
		return E.Errors(err, s.closeListeners())
	}
	backend, err := ECommon.PrepareSharedNetwork(cgroupBackend, ECommon.SharedNetworkConfig{
		ListenerPort:         s.listeners.selectedPort(),
		EnableTCP:            s.inbound.enableTCP,
		EnableUDP:            s.inbound.enableUDP,
		HijackDNS:            s.inbound.dnsMode == dnsModeHijack,
		BypassPrivateAddress: s.inbound.bypassPrivateAddress,
		RedirectIPv4:         s.inbound.redirectIPv4Prefix,
		RedirectIPv6:         s.inbound.redirectIPv6Prefix,
		IncludeSourceCIDR:    s.inbound.sharedNetworkOptions.IncludeSourceCIDR,
		ExcludeSourceCIDR:    s.inbound.sharedNetworkOptions.ExcludeSourceCIDR,
		IncludeSourceMAC:     s.inbound.sharedNetworkIncludeMAC,
		ExcludeSourceMAC:     s.inbound.sharedNetworkExcludeMAC,
		MapCapacity:          s.mapCapacity,
		UDPTimeout:           s.inbound.udpTimeout,
	})
	if err != nil {
		return E.Errors(err, s.closeListeners())
	}
	s.setSharedBackend(backend)
	if cgroupBackend == nil {
		if _, err = backend.UpdateBypassCIDR(s.inbound.currentBypassCIDR()); err != nil {
			return E.Errors(err, s.Close())
		}
	} else if err = backend.SetBypassCIDRState(s.inbound.currentBypassCIDR()); err != nil {
		return E.Errors(err, s.Close())
	}
	s.tcManager = &sharedTCManager{
		backend:        backend,
		logger:         s.inbound.logger,
		interfaces:     s.interfaces,
		enableIPv4:     s.inbound.redirectIPv4Prefix.IsValid(),
		priority:       s.tcPriority,
		networkMonitor: s.inbound.networkManager.NetworkMonitor(),
		attachments:    make(map[string]*sharedTCAttachment),
	}
	if err = s.tcManager.Start(); err != nil {
		return E.Errors(err, s.Close())
	}
	bypassMapSource := "local_cgroup"
	if cgroupBackend == nil {
		bypassMapSource = "standalone"
	}
	s.inbound.logger.Info(
		"eBPF shared-network TC interception ready: downstream_interfaces=[", s.tcManager.InterfaceString(),
		"], redirect_listener_port=", s.listeners.selectedPort(),
		", dns_mode=", s.inbound.dnsMode,
		", bypass_maps=", bypassMapSource,
		", bypass_private_address=", s.inbound.bypassPrivateAddress,
		", source_cidr={include:", len(s.inbound.sharedNetworkOptions.IncludeSourceCIDR),
		", exclude:", len(s.inbound.sharedNetworkOptions.ExcludeSourceCIDR), "}",
		", source_mac={include:", len(s.inbound.sharedNetworkIncludeMAC),
		", exclude:", len(s.inbound.sharedNetworkExcludeMAC), "}",
		", tc_priority=", s.tcPriority,
		", map_capacity={proxy:", s.mapCapacity.Proxy,
		", bypass:", s.mapCapacity.Bypass,
		", fragment:", s.mapCapacity.Fragment, "}",
		", programs=[tc/ingress, tc/egress]",
	)
	return nil
}

func (s *sharedNetwork) startListeners() error {
	err := s.listeners.start(
		s.inbound.enableTCP,
		s.inbound.enableUDP,
		s.inbound.redirectIPv4Prefix.IsValid(),
		s.inbound.redirectIPv6Prefix.IsValid(),
		s.newListener,
	)
	if err == nil {
		s.inbound.logger.Debug("eBPF shared-network redirect listeners ready: [", s.listeners.String(), "]")
	}
	return err
}

func (s *sharedNetwork) newListener(network string, ipv6Listener bool, port uint16) *listener.Listener {
	return s.inbound.newInternalListener(s, network, ipv6Listener, port)
}

func (s *sharedNetwork) InterfaceUpdated() {
	s.udpNat.Purge()
	s.lifecycleAccess.RLock()
	defer s.lifecycleAccess.RUnlock()
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
	s.udpNat.Purge()
	if s.tcManager != nil {
		if err := s.tcManager.Close(); err != nil {
			return err
		}
		s.tcManager = nil
	}
	var backendErr error
	if backend := s.sharedBackendInstance(); backend != nil {
		backendErr = backend.Close()
		if backend.IsClosed() {
			s.setSharedBackend(nil)
		}
	}
	return E.Errors(backendErr, s.closeListeners())
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

func (s *sharedNetwork) setSharedBackend(backend *ECommon.SharedNetworkBackend) {
	s.backendAccess.Lock()
	s.sharedBackend = backend
	s.backendAccess.Unlock()
}
