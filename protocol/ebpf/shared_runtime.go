//go:build with_ebpf && (linux || android)

package ebpf

import (
	kernelRuntime "github.com/CHIZI-0618/sing-ebpf/runtime"
)

type sharedKernelRuntime = kernelRuntime.SharedPacketRewriteRuntime
type sharedKernelRuntimeHooks = kernelRuntime.SharedPacketRewriteHooks

func newSharedKernelRuntime(hooks sharedKernelRuntimeHooks, priority uint16) sharedKernelRuntime {
	return kernelRuntime.NewSharedPacketRewriteRuntime(kernelRuntime.SharedPacketRewriteRuntimeConfig{
		Hooks:    hooks,
		Priority: priority,
	})
}

func (s *sharedRewrite) kernelRuntimeHooks() sharedKernelRuntimeHooks {
	return sharedKernelRuntimeHooks{
		PrepareBackend:     s.prepareBackend,
		PurgeUserspaceFlow: s.udpNat.Purge,
		Ready:              s.sharedRewriteReady,
		WarnFlowPurge: func(interfaceName string, err error) {
			s.janitorWarnings.warn(s.inbound.logger, "purge shared packet-rewrite state for ", interfaceName, ": ", err)
		},
	}
}
