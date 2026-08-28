//go:build with_ebpf && !ebpf_debug && (linux || android)

package ebpf

import ECommon "github.com/sagernet/sing-box/common/ebpf"

type eBPFDebugState struct{}

func (i *Inbound) startDebug() {}

func (i *Inbound) logDebugSnapshot(string) {}

func (i *Inbound) logDebugLocalDetails(*ECommon.CgroupBackend) {}

func (i *Inbound) logDebugSharedDetails(*sharedNetwork) {}

func (i *Inbound) logDebugBypassRuleSetExtraction(int) {}

func (i *Inbound) logDebugBypassCIDRUpdate() {}

func (i *Inbound) logDebugLocalTCPCleanup(ECommon.CgroupTCPRedirectSweepResult) {}

func (i *Inbound) logDebugSharedFlowCleanup(ECommon.SharedNetworkFlowSweepResult) {}

func (i *Inbound) stopDebug() error { return nil }
