//go:build with_ebpf && ebpf_debug && (linux || android)

package ebpf

import (
	"encoding/json"
	"strings"

	ECommon "github.com/sagernet/sing-box/common/ebpf"
	"github.com/sagernet/sing-box/log"
)

type eBPFDebugState struct {
	started             bool
	programStatsRelease func() error
}

type eBPFDebugSnapshot struct {
	Phase  string                      `json:"phase"`
	Local  *ECommon.DebugRuntimeStatus `json:"local,omitempty"`
	Shared *ECommon.DebugRuntimeStatus `json:"shared,omitempty"`
}

func (i *Inbound) startDebug() {
	if i.debug.started {
		return
	}
	i.debug.started = true
	release, err := ECommon.AcquireProgramRuntimeStats()
	if err != nil {
		i.logger.Warn("enable eBPF program runtime statistics: ", err)
		return
	}
	i.debug.programStatsRelease = release
	i.logger.Info("eBPF debug instrumentation enabled")
}

func (i *Inbound) logDebugSnapshot(phase string) {
	if !i.debug.started || !ebpfDebugLoggingEnabled(i.logger) {
		return
	}
	snapshot := eBPFDebugSnapshot{Phase: phase}
	if backend := i.cgroupBackendInstance(); backend != nil {
		status := backend.DebugRuntimeStatus()
		snapshot.Local = &status
	}
	if shared := i.sharedNetwork; shared != nil {
		if backend := shared.sharedBackendInstance(); backend != nil {
			status := backend.DebugRuntimeStatus()
			snapshot.Shared = &status
		}
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		i.logger.Debug("marshal eBPF debug snapshot: ", err)
		return
	}
	i.logger.Debug("eBPF debug snapshot: ", string(encoded))
}

func (i *Inbound) logDebugLocalDetails(backend *ECommon.CgroupBackend) {
	if !ebpfDebugLoggingEnabled(i.logger) {
		return
	}
	i.logger.Debug(
		"eBPF local cgroup details: fakeip_force=[", i.fakeIPPrefixString(), "]",
		", self_bypass=socket_cookie",
		", internal_redirect_prefix=[", strings.Join(i.redirectAddressStrings(), ", "), "]",
		", state_capacity={tcp_redirect:", i.cgroupMapCapacity.TCPRedirect,
		", udp_redirect:", i.cgroupMapCapacity.UDPRedirect,
		", udp_peer:", i.cgroupMapCapacity.UDPPeer,
		", udp_flow:", i.cgroupMapCapacity.UDPFlow,
		", udp_recovery:", min(i.cgroupMapCapacity.UDPRedirect, uint32(ECommon.UDPRecoveryMapCapacity)),
		", socket_bypass:", i.cgroupMapCapacity.SocketBypass, "}",
		", tcp_redirect_stale_timeout=", localTCPRedirectMaxAge,
		", programs=[", strings.Join(backend.AttachedPrograms(), ", "), "]",
	)
}

func (i *Inbound) logDebugSharedDetails(shared *sharedNetwork) {
	if !ebpfDebugLoggingEnabled(i.logger) {
		return
	}
	i.logger.Debug(
		"eBPF shared-network details: fakeip_force=[", i.fakeIPPrefixString(), "]",
		", tc_priority=", shared.tcPriority,
		", state_capacity={proxy:", shared.mapCapacity.Proxy,
		", bypass:", shared.mapCapacity.Bypass, "}",
		", programs=[tc/ingress, tc/egress]",
	)
}

func (i *Inbound) logDebugBypassRuleSetExtraction(rawPrefixCount int) {
	if !ebpfDebugLoggingEnabled(i.logger) {
		return
	}
	i.logger.Debug(
		"extracted eBPF bypass CIDRs: rule_sets=", len(i.bypassRuleSet),
		", raw_prefixes=", rawPrefixCount,
	)
}

func (i *Inbound) logDebugBypassCIDRUpdate() {
	if !ebpfDebugLoggingEnabled(i.logger) {
		return
	}
	var ipv4Count, ipv6Count int
	var countLoaded bool
	if backend := i.cgroupBackendInstance(); backend != nil {
		ipv4Count, ipv6Count = backend.BypassCIDRCount()
		countLoaded = true
	} else if i.sharedNetwork != nil {
		if backend := i.sharedNetwork.sharedBackendInstance(); backend != nil {
			ipv4Count, ipv6Count = backend.BypassCIDRCount()
			countLoaded = true
		}
	}
	if !countLoaded {
		ipv4Count, ipv6Count = i.bypassRuleSetPolicy.Count()
	}
	i.logger.Debug("refreshed eBPF bypass CIDR policy: ipv4=", ipv4Count, ", ipv6=", ipv6Count)
}

func (i *Inbound) logDebugLocalTCPCleanup(result ECommon.CgroupTCPRedirectSweepResult) {
	if !ebpfDebugLoggingEnabled(i.logger) || result.Removed == 0 {
		return
	}
	i.logger.Debug(
		"eBPF local TCP redirect cleanup: scanned=", result.Scanned,
		", removed=", result.Removed,
		", complete=", result.Complete,
	)
}

func (i *Inbound) logDebugSharedFlowCleanup(result ECommon.SharedNetworkFlowSweepResult) {
	if !ebpfDebugLoggingEnabled(i.logger) || result.Removed == 0 {
		return
	}
	i.logger.Debug(
		"eBPF shared-network flow cleanup: scanned=", result.Scanned,
		", removed=", result.Removed,
		", retained=", result.Retained,
		", proxy_state=", result.Usage.Entries, "/", result.Usage.Capacity,
		", complete=", result.Complete,
	)
}

func (i *Inbound) stopDebug() error {
	if !i.debug.started {
		return nil
	}
	i.logDebugSnapshot("shutdown")
	i.debug.started = false
	release := i.debug.programStatsRelease
	i.debug.programStatsRelease = nil
	if release == nil {
		return nil
	}
	return release()
}

func ebpfDebugLoggingEnabled(logger any) bool {
	levelProvider, available := logger.(interface{ Level() log.Level })
	return !available || levelProvider.Level() >= log.LevelDebug
}
