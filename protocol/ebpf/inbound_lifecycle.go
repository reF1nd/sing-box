//go:build with_ebpf && (linux || android)

package ebpf

import (
	"github.com/sagernet/sing-box/adapter"
	ECommon "github.com/sagernet/sing-box/common/ebpf"
	E "github.com/sagernet/sing/common/exceptions"
)

func (i *Inbound) Start(stage adapter.StartStage) error {
	switch stage {
	case adapter.StartStateInitialize:
		i.startDebug()
		if err := i.startSocketProtection(); err != nil {
			return err
		}
		if err := i.selectRedirectPrefixes(); err != nil {
			return err
		}
		if i.cgroupEnabled && i.androidUIDOptions == nil {
			if err := i.prepareCgroupBackend(); err != nil {
				return err
			}
		}
		if i.sharedNetworkEnabled {
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
			return combineStartError(E.New("eBPF backend is not initialized"), i.cleanupStartFailure())
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
			if i.enableTCP {
				i.startTCPRedirectJanitor()
			}
			bypassIPv4Count, bypassIPv6Count := backend.BypassCIDRCount()
			i.logger.Info(
				"eBPF local cgroup interception ready: cgroup=", backend.CgroupPath(),
				", redirect_listener_port=", i.listeners.selectedPort(),
				", dns_mode=", i.localDNSMode,
				", ipv6=", i.cgroupIPv6Enabled(),
				", bypass_private_address=", i.localBypassPrivateAddress,
				", udp_state_cleanup=", backend.UDPCleanupMode(),
				", uid_policy={include_configured:", i.cgroupPolicy.IncludeUIDConfigured,
				", include:[", formatUIDRanges(i.cgroupPolicy.IncludeUID), "]",
				", exclude:[", formatUIDRanges(i.cgroupPolicy.ExcludeUID), "]}",
				", bypass_cidr={ipv4:", bypassIPv4Count, ", ipv6:", bypassIPv6Count, "}",
			)
			i.logDebugLocalDetails(backend)
		}
		i.logDebugSnapshot("startup")
	}
	return nil
}

func (i *Inbound) prepareCgroupBackend() error {
	policy := i.cgroupPolicy
	policy.EnableBypassCIDR = true
	backend, err := ECommon.PrepareCgroup(ECommon.CgroupConfig{
		Path:         i.cgroupPath,
		EnableTCP:    i.enableTCP,
		EnableUDP:    i.enableUDP,
		EnableIPv6:   i.cgroupIPv6Enabled(),
		RedirectIPv4: i.redirectIPv4Prefix,
		RedirectIPv6: i.redirectIPv6Prefix,
		FakeIPIPv4:   i.fakeIPIPv4Prefix,
		FakeIPIPv6:   i.fakeIPIPv6Prefix,
		MapCapacity:  i.cgroupMapCapacity,
		UDPTimeout:   i.udpTimeout,
		Policy:       policy,
	})
	if err != nil {
		return err
	}
	if err = i.socketProtector.Attach(backend); err != nil {
		closeErr := backend.Close()
		if closeErr != nil {
			closeErr = E.Cause(closeErr, "close eBPF backend")
		}
		return E.Errors(err, closeErr)
	}
	i.setCgroupBackend(backend)
	return nil
}

func (i *Inbound) startSocketProtection() error {
	if i.socketProtector == nil || i.socketProtectionRegistration != nil {
		return nil
	}
	registration, err := adapter.RegisterEBPFSocketProtection(i.ctx, i.socketProtector.ControlFunc())
	if err != nil {
		return E.Cause(err, "register eBPF socket protection")
	}
	i.socketProtectionRegistration = registration
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
	debugErr := i.stopDebug()
	i.stopTCPRedirectJanitor()
	i.stopBypassRuleSets()
	i.closeSocketProtection()
	backend := i.takeCgroupBackend()
	var sharedErr error
	if i.sharedNetwork != nil {
		sharedErr = i.sharedNetwork.Close()
		if !i.sharedNetwork.IsClosed() {
			i.setCgroupBackend(backend)
			if sharedErr == nil {
				sharedErr = E.New("shared-network eBPF backend remained open after close")
			}
			return sharedErr
		}
		i.sharedNetwork = nil
	}
	var backendErr error
	if backend != nil {
		backendErr = backend.Close()
		if !backend.IsClosed() {
			i.setCgroupBackend(backend)
			if backendErr == nil {
				backendErr = E.New("eBPF backend remained open after close")
			}
			return backendErr
		}
	}
	listenerErr := i.closeListeners()
	i.udpNat.Purge()
	return E.Errors(sharedErr, backendErr, listenerErr, debugErr, i.removeLocalRoutes())
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

func (i *Inbound) takeCgroupBackend() *ECommon.CgroupBackend {
	i.cgroupBackendAccess.Lock()
	backend := i.cgroupBackend
	i.cgroupBackend = nil
	i.cgroupBackendAccess.Unlock()
	return backend
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

func (i *Inbound) closeSocketProtection() {
	if i.socketProtectionRegistration != nil {
		i.socketProtectionRegistration.Close()
		i.socketProtectionRegistration = nil
	}
	if i.socketProtector != nil {
		i.socketProtector.Close()
	}
}
