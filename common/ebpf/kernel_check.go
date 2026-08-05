package ebpf

import _ "embed"

//go:embed check-kernel.sh
var kernelCheckScript string

// KernelCheckScript returns the portable, non-disruptive eBPF capability probe.
func KernelCheckScript() string {
	return kernelCheckScript
}
