//go:build !with_ebpf || (!linux && !android)

package route

//nolint:unused // storage type for the build-tagged NetworkManager field
type ebpfSelfBypassState struct{}
