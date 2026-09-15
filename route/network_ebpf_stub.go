//go:build !with_ebpf || (!linux && !android)

package route

//nolint:unused // keeps NetworkManager platform-neutral when eBPF is unavailable
type ebpfSelfBypassState struct{}
