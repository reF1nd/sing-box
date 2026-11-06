//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"slices"
	"time"
)

// tcInterfaceHealthCheck is the cheap, read-only watchdog stage. It uses the
// monitor's cached topology and the runtimes' already-owned resource list; it
// deliberately avoids UpdateInterfaces, map refreshes, flow purges and any
// netlink/sysctl mutation. A false result immediately falls through to the
// existing full reconciliation path.
func (i *Inbound) tcInterfaceHealthCheck(ctx context.Context) (healthy bool) {
	defer func() { i.recordTCHealthCheck(healthy) }()
	if ctx.Err() != nil {
		return true
	}
	i.lifecycleAccess.Lock()
	defer i.lifecycleAccess.Unlock()
	if ctx.Err() != nil {
		return true
	}
	defaultInterface := i.monitoredDefaultInterfaceName()
	localInterface, err := availableLocalTCInterface(i.localSocketAssignEnabled(), defaultInterface)
	if err != nil {
		return false
	}
	sharedInterfaces := activeSharedInterfaces(i.sharedOptions.Interface, defaultInterface, i.sharedOptions.DefaultInterface)
	tcSharedInterfaces := sharedInterfaces
	if i.sharedRewriteEnabled() {
		tcSharedInterfaces = nil
	}
	hostAddresses := i.hostAddresses()

	i.tcDataPlaneAccess.RLock()
	dataPlane := i.tcDataPlane
	if dataPlane != nil {
		healthy, checkErr := dataPlane.HealthCheck(localInterface, tcSharedInterfaces, hostAddresses)
		if checkErr != nil || !healthy {
			i.tcDataPlaneAccess.RUnlock()
			return false
		}
	}
	i.tcDataPlaneAccess.RUnlock()

	if shared := i.sharedRewriteInstance(); shared != nil {
		if dataPlane := shared.dataPlaneInstance(); dataPlane != nil {
			healthy, checkErr := dataPlane.HealthCheck(sharedInterfaces, hostAddresses)
			if checkErr != nil || !healthy {
				return false
			}
		}
	}
	return true
}

func nextTCRetryDelay(current time.Duration) time.Duration {
	if current <= 0 {
		return tcRetryInitialDelay
	}
	next := current * 2
	if next > tcRetryMaximumDelay {
		return tcRetryMaximumDelay
	}
	return next
}

// updateTCInterfaces runs one reconciliation pass and reports what each of
// tcUpdateOutcome's three components made of it: sharedRewrite from the
// shared packet-rewrite step alone (unchanged from before this scheduler also
// covered the other two -- a shared packet-rewrite recovery must not be
// cancelled by an unrelated success), general from every other TC step below
// (inventory, topology, infrastructure, the attachment reconcile, host
// policy), and bypassRuleSet from retrying a previously-failed bypass_rule_set
// refresh. general is left at its zero value (tcSharedRewriteUnknown) only
// while genuinely nothing in this pass has run it yet; every path that
// returns after touching it leaves it Recoverable or Settled, since it runs
// unconditionally every round.
func (i *Inbound) updateTCInterfaces(ctx context.Context) (outcome tcUpdateOutcome) {
	if ctx.Err() != nil {
		return
	}
	networkGeneration := i.currentNetworkGeneration()
	defer i.recordTCReconcile()
	i.lifecycleAccess.Lock()
	defer i.lifecycleAccess.Unlock()
	if ctx.Err() != nil {
		return
	}
	i.sweepTCAssignments()
	outcome.bypassRuleSet = i.retryBypassRuleSetIfNeededLocked()
	if err := i.networkManager.UpdateInterfaces(); err != nil {
		i.interfaceWarnings.inventory.warn(i.logger, "update interfaces for TC eBPF: ", err)
		outcome.general = tcSharedRewriteRecoverable
	}
	defaultInterface := i.monitoredDefaultInterfaceName()
	localSocketAssignEnabled := i.localSocketAssignEnabled()
	localInterface, err := availableLocalTCInterface(localSocketAssignEnabled, defaultInterface)
	if err != nil {
		i.interfaceWarnings.topology.warn(i.logger, "inspect TC eBPF local interface: ", err)
		outcome.general = tcSharedRewriteRecoverable
		return
	}
	if localSocketAssignEnabled && localInterface == "" {
		message := []any{"eBPF TC local path waiting for default interface; retaining current attachment state"}
		i.interfaceWarnings.defaultInterface.record(time.Now(), message...)
		if _, changed := i.interfaceWarnings.defaultInterfaceState.transition("unavailable"); changed {
			i.logger.Warn("eBPF ", ebpfStructuredEvent("tc_local_waiting", map[string]any{
				"state":  "waiting_for_interface",
				"reason": "default_interface_unavailable",
			}))
		}
	} else if localSocketAssignEnabled {
		previous, changed := i.interfaceWarnings.defaultInterfaceState.transition("available")
		if changed && previous == "unavailable" {
			i.logger.Info("eBPF ", ebpfStructuredEvent("tc_local_restored", map[string]any{
				"default_interface": localInterface,
				"state":             "available",
			}))
		}
	} else {
		i.interfaceWarnings.defaultInterfaceState.transition("not_configured")
	}
	sharedInterfaces := activeSharedInterfaces(i.sharedOptions.Interface, defaultInterface, i.sharedOptions.DefaultInterface)
	tcSharedInterfaces := sharedInterfaces
	if i.sharedRewriteEnabled() {
		tcSharedInterfaces = nil
	}
	hostAddresses := i.hostAddresses()
	var sharedDataPlane sharedKernelRuntime
	if shared := i.sharedRewriteInstance(); shared != nil {
		sharedDataPlane = shared.dataPlaneInstance()
	}
	if sharedDataPlane != nil {
		previous := sharedDataPlane.AttachmentDiagnostics()
		if err = sharedDataPlane.Reconcile(sharedInterfaces, hostAddresses); err != nil {
			i.counters.sharedReconcileFailures.Add(1)
			i.interfaceWarnings.reconcile.warn(i.logger, "refresh shared packet-rewrite interfaces: ", err)
			if sharedDataPlane.BackendClosed() || sharedDataPlane.RequiresRebuild() {
				outcome.sharedRewrite = tcSharedRewriteUnrecoverable
			} else {
				outcome.sharedRewrite = tcSharedRewriteRecoverable
			}
		} else {
			outcome.sharedRewrite = tcSharedRewriteSettled
			if attachments := sharedDataPlane.AttachmentDiagnostics(); !slices.Equal(previous, attachments) {
				i.logger.Debug("eBPF ", ebpfStructuredEvent("shared_attachments_changed", map[string]any{
					"previous": previous,
					"current":  attachments,
				}))
			}
		}
	} else {
		outcome.sharedRewrite = tcSharedRewriteSettled
	}
	infrastructureChanged, err := i.repairTCInfrastructure()
	infrastructureHealthy := err == nil
	if err != nil {
		i.interfaceWarnings.infrastructure.warn(i.logger, "repair TC eBPF network state: ", err)
		outcome.general = tcSharedRewriteRecoverable
	}
	changed, err := i.tcAttachmentStateChanged(localInterface, tcSharedInterfaces)
	if err != nil {
		i.interfaceWarnings.topology.warn(i.logger, "inspect TC eBPF interfaces: ", err)
		outcome.general = tcSharedRewriteRecoverable
		return
	}
	if !changed {
		if err = i.updateTCHostAddresses(hostAddresses); err != nil {
			i.interfaceWarnings.hostPolicy.warn(i.logger, "refresh TC eBPF host addresses: ", err)
			outcome.general = tcSharedRewriteRecoverable
		}
		if err = i.updateCgroupHostAddresses(hostAddresses); err != nil {
			i.interfaceWarnings.hostPolicy.warn(i.logger, "refresh cgroup eBPF host addresses: ", err)
			outcome.general = tcSharedRewriteRecoverable
		}
		if infrastructureChanged && infrastructureHealthy {
			i.logger.Info("eBPF ", ebpfStructuredEvent("tc_network_restored", map[string]any{
				"network_generation": networkGeneration,
			}))
		}
		if outcome.general == tcSharedRewriteUnknown {
			outcome.general = tcSharedRewriteSettled
		}
		return
	}
	previousAttachments := i.tcAttachmentDiagnostics()
	if err = i.reconcileTCDataPlane(localInterface, tcSharedInterfaces, hostAddresses); err != nil {
		i.interfaceWarnings.reconcile.warn(i.logger, "refresh TC eBPF interfaces: ", err)
		outcome.general = tcSharedRewriteRecoverable
		return
	}
	i.warnIfLocalFakeIPICMPIPv6Unroutable(localInterface)
	if err = i.updateCgroupHostAddresses(hostAddresses); err != nil {
		i.interfaceWarnings.hostPolicy.warn(i.logger, "refresh cgroup eBPF host addresses: ", err)
		outcome.general = tcSharedRewriteRecoverable
	}
	attachments := i.tcAttachmentDiagnostics()
	if !slices.Equal(previousAttachments, attachments) {
		i.logger.Info("eBPF ", ebpfStructuredEvent("tc_attachments_changed", map[string]any{
			"previous":           previousAttachments,
			"current":            attachments,
			"network_generation": networkGeneration,
		}))
	}
	if outcome.general == tcSharedRewriteUnknown {
		outcome.general = tcSharedRewriteSettled
	}
	return outcome
}

func (i *Inbound) sweepTCAssignments() {
	// The bounded assignment maintenance worker owns scans. Interface
	// reconciliation only provides an event wake so scans are not tied to the
	// drift-check cadence.
	i.requestTCAssignmentMaintenance()
}
