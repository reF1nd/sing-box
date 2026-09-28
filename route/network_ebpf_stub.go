//go:build !with_ebpf || (!linux && !android)

package route

type ebpfSelfBypassState struct{} //nolint:unused // Storage type for the build-tagged NetworkManager field.
