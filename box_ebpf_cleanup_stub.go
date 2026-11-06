//go:build !with_ebpf || (!linux && !android)

package box

func retryRetainedEBPFResources() error {
	return nil
}

func retryRetainedEBPFResourcesOnClose() error {
	return nil
}
