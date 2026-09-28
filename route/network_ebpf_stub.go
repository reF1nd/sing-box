//go:build !with_ebpf || (!linux && !android)

package route

type ebpfSelfBypassState struct{}
