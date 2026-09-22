//go:build with_ebpf && (linux || android)

package ebpf

import (
	commonEBPF "github.com/CHIZI-0618/sing-ebpf"
	kernelRuntime "github.com/CHIZI-0618/sing-ebpf/runtime"
)

// Consumer-side aliases keep the adapter independent of the implementation
// package's concrete resource types.
type (
	tcRuntime       = kernelRuntime.TCRuntime
	tcRuntimeConfig = kernelRuntime.TCRuntimeConfig
)

func newTCRuntime(backend *commonEBPF.TCBackend, config tcRuntimeConfig) (tcRuntime, error) {
	config.Backend = backend
	return kernelRuntime.NewTCRuntime(config)
}

func newUnstartedTCRuntime(backend *commonEBPF.TCBackend) tcRuntime {
	return kernelRuntime.NewUnstartedTCRuntime(backend)
}
