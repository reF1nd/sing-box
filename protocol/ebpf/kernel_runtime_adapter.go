//go:build with_ebpf && (linux || android)

package ebpf

import commonEBPF "github.com/CHIZI-0618/sing-ebpf"

// kernelRuntimeOwner is the complete sing-ebpf diagnostics boundary used by
// the inbound. Backend-specific resource IDs and metadata stay inside the
// library; the API adapter consumes only the resulting runtime snapshot.
type kernelRuntimeOwner interface {
	RuntimeResources() commonEBPF.RuntimeResources
}

func inspectKernelRuntimeOwners(owners ...kernelRuntimeOwner) commonEBPF.RuntimeState {
	resources := make([]commonEBPF.RuntimeResources, 0, len(owners))
	for _, owner := range owners {
		if owner != nil {
			resources = append(resources, owner.RuntimeResources())
		}
	}
	return commonEBPF.InspectRuntimeResources(resources...)
}
