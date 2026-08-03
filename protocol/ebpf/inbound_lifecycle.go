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
		if i.cgroupEnabled {
			policy := i.cgroupPolicy
			policy.EnableBypassCIDR = true
			backend, err := ECommon.PrepareCgroup(ECommon.CgroupConfig{
				Path:         i.cgroupPath,
				EnableTCP:    i.enableTCP,
				EnableUDP:    i.enableUDP,
				RedirectIPv4: i.redirectIPv4Prefix,
				RedirectIPv6: i.redirectIPv6Prefix,
				MapCapacity:  i.cgroupMapCapacity,
				Policy:       policy,
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
		}
		if i.sharedNetworkOptions.Enabled {
			i.sharedNetwork = newSharedNetwork(i, i.sharedNetworkOptions)
		}
	case adapter.StartStateStart:
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
			if i.enableUDP && !backend.UsesSocketRelease() {
				i.logger.Warn(
					"cgroup socket-release is unavailable; using LRU cleanup fallback for UDP redirect state",
				)
			}
			bypassIPv4Count, bypassIPv6Count := backend.BypassCIDRCount()
			i.logger.Info(
				"eBPF local cgroup interception ready: cgroup=", backend.CgroupPath(),
				", redirect_listener_port=", i.listeners.selectedPort(),
				", dns_mode=", i.dnsMode,
				", self_bypass=", backend.SelfBypassMode(),
				", redirect_address=[", strings.Join(i.redirectAddressStrings(), ", "), "]",
				", bypass_cidr={ipv4:", bypassIPv4Count, ", ipv6:", bypassIPv6Count, "}",
				", map_capacity={tcp_redirect:", i.cgroupMapCapacity.TCPRedirect,
				", udp_redirect:", i.cgroupMapCapacity.UDPRedirect,
				", socket_bypass:", i.cgroupMapCapacity.SocketBypass, "}",
				", programs=[", strings.Join(backend.AttachedPrograms(), ", "), "]",
			)
		}
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
