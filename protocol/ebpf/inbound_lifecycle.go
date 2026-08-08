//go:build with_ebpf && (linux || android)

package ebpf

import (
	"strings"

	"github.com/sagernet/sing-box/adapter"
	ECommon "github.com/sagernet/sing-box/common/ebpf"
	E "github.com/sagernet/sing/common/exceptions"
)

func (i *Inbound) Start(stage adapter.StartStage) error {
	switch stage {
	case adapter.StartStateInitialize:
		if i.cgroupEnabled && i.androidUIDOptions == nil {
			if err := i.prepareCgroupBackend(); err != nil {
				return err
			}
		}
		if i.sharedNetworkOptions.Enabled {
			i.sharedNetwork = newSharedNetwork(i, i.sharedNetworkOptions)
		}
	case adapter.StartStateStart:
		if i.cgroupEnabled && i.androidUIDOptions != nil {
			if err := i.resolveAndroidUIDPolicy(); err != nil {
				return combineStartError(E.Cause(err, "resolve Android UID policy"), i.cleanupStartFailure())
			}
			if err := i.prepareCgroupBackend(); err != nil {
				return combineStartError(err, i.cleanupStartFailure())
			}
		}
		backend := i.cgroupBackendInstance()
		if i.cgroupEnabled && backend == nil {
			return E.New("eBPF backend is not initialized")
		}
		if err := i.startBypassRuleSets(); err != nil {
			return combineStartError(
				E.Cause(err, "initialize eBPF bypass_rule_set"),
				i.cleanupStartFailure(),
			)
		}
		if err := i.setupLocalRoutes(); err != nil {
			return combineStartError(
				E.Cause(err, "configure eBPF redirect routes"),
				i.cleanupStartFailure(),
			)
		}
		if i.cgroupEnabled {
			if err := i.startListeners(); err != nil {
				return combineStartError(err, i.cleanupStartFailure())
			}
			if err := backend.LoadPrograms(i.listeners.selectedPort()); err != nil {
				return combineStartError(err, i.cleanupStartFailure())
			}
		}
		if i.sharedNetwork != nil {
			if err := i.sharedNetwork.Start(backend); err != nil {
				return combineStartError(err, i.cleanupStartFailure())
			}
		}
		if i.cgroupEnabled {
			if err := backend.Attach(); err != nil {
				return combineStartError(err, i.cleanupStartFailure())
			}
			if i.cgroupIPv6Mode == cgroupIPv6ModeAuto && i.cgroupIPv6Enabled() {
				i.logger.Info("eBPF local cgroup IPv6 interception: available=", i.cgroupIPv6Available)
			}
			if i.enableUDP && !backend.UsesSocketRelease() {
				i.logger.Warn(
					"cgroup socket-release is unavailable; using LRU cleanup fallback for UDP redirect state",
				)
			}
			bypassIPv4Count, bypassIPv6Count := backend.BypassCIDRCount()
			selfBypassMode := backend.SelfBypassMode()
			socketBypassCapacity := i.cgroupMapCapacity.SocketBypass
			if selfBypassMode == "tgid" {
				socketBypassCapacity = 0
			}
			i.logger.Info(
				"eBPF local cgroup interception ready: cgroup=", backend.CgroupPath(),
				", redirect_listener_port=", i.listeners.selectedPort(),
				", dns_mode=", i.dnsMode,
				", cgroup_ipv6_mode=", i.cgroupIPv6Mode,
				", self_bypass=", selfBypassMode,
				", redirect_address=[", strings.Join(i.redirectAddressStrings(), ", "), "]",
				", bypass_cidr={ipv4:", bypassIPv4Count, ", ipv6:", bypassIPv6Count, "}",
				", map_capacity={tcp_redirect:", i.cgroupMapCapacity.TCPRedirect,
				", udp_redirect:", i.cgroupMapCapacity.UDPRedirect,
				", socket_bypass:", socketBypassCapacity, "}",
				", programs=[", strings.Join(backend.AttachedPrograms(), ", "), "]",
			)
		}
	}
	return nil
}

func (i *Inbound) prepareCgroupBackend() error {
	if err := i.refreshCgroupIPv6Availability(true); err != nil {
		return err
	}
	policy := i.cgroupPolicy
	policy.EnableBypassCIDR = true
	backend, err := ECommon.PrepareCgroup(ECommon.CgroupConfig{
		Path:          i.cgroupPath,
		EnableTCP:     i.enableTCP,
		EnableUDP:     i.enableUDP,
		EnableIPv6:    i.cgroupIPv6Enabled(),
		AutoIPv6:      i.cgroupIPv6Mode == cgroupIPv6ModeAuto && i.cgroupIPv6Enabled(),
		IPv6Available: i.cgroupIPv6Available,
		RedirectIPv4:  i.redirectIPv4Prefix,
		RedirectIPv6:  i.redirectIPv6Prefix,
		MapCapacity:   i.cgroupMapCapacity,
		UDPTimeout:    i.udpTimeout,
		Policy:        policy,
	})
	if err != nil {
		return err
	}
	i.setCgroupBackend(backend)
	protectManager, loaded := i.networkManager.(adapter.SocketProtectManager)
	if !loaded {
		closeErr := backend.Close()
		if backend.IsClosed() {
			i.setCgroupBackend(nil)
		}
		return E.Errors(E.New("network manager does not support socket protection"), closeErr)
	}
	if err = protectManager.RegisterSocketProtectFunc(backend.SocketProtectFunc()); err != nil {
		closeErr := backend.Close()
		if backend.IsClosed() {
			i.setCgroupBackend(nil)
		}
		if closeErr != nil {
			closeErr = E.Cause(closeErr, "close eBPF backend")
		}
		return E.Errors(err, closeErr)
	}
	i.protectRegistered = true
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
	i.resetCgroupIPv6ProbeLocked()
	i.udpNat.Purge()
	i.stopBypassRuleSets()
	var sharedErr error
	if i.sharedNetwork != nil {
		sharedErr = i.sharedNetwork.Close()
		if !i.sharedNetwork.IsClosed() {
			if sharedErr == nil {
				sharedErr = E.New("shared-network eBPF backend remained open after close")
			}
			return sharedErr
		}
		i.sharedNetwork = nil
	}
	backend := i.cgroupBackendInstance()
	var backendErr error
	if backend != nil {
		backendErr = backend.Close()
		if !backend.IsClosed() {
			if backendErr == nil {
				backendErr = E.New("eBPF backend remained open after close")
			}
			return backendErr
		}
		i.setCgroupBackend(nil)
	}
	i.unregisterSocketProtector()
	return E.Errors(sharedErr, backendErr, i.closeListeners(), i.removeLocalRoutes())
}

func (i *Inbound) cgroupBackendInstance() *ECommon.CgroupBackend {
	i.cgroupBackendAccess.RLock()
	defer i.cgroupBackendAccess.RUnlock()
	return i.cgroupBackend
}

func (i *Inbound) setCgroupBackend(backend *ECommon.CgroupBackend) {
	i.cgroupBackendAccess.Lock()
	i.cgroupBackend = backend
	i.cgroupBackendAccess.Unlock()
}

func (i *Inbound) redirectAddressStrings() []string {
	addresses := make([]string, 0, 2)
	if i.redirectIPv4Prefix.IsValid() {
		addresses = append(addresses, i.redirectIPv4Prefix.String())
	}
	if i.redirectIPv6Prefix.IsValid() {
		addresses = append(addresses, i.redirectIPv6Prefix.String())
	}
	return addresses
}

func (i *Inbound) unregisterSocketProtector() {
	if !i.protectRegistered {
		return
	}
	if protectManager, loaded := i.networkManager.(adapter.SocketProtectManager); loaded {
		protectManager.UnregisterSocketProtectFunc()
	}
	i.protectRegistered = false
}
