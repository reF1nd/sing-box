//go:build with_ebpf && (linux || android)

package box

import (
	"time"

	"github.com/sagernet/sing-box/internal/ebpfcleanup"
	E "github.com/sagernet/sing/common/exceptions"
)

const (
	ebpfCloseRetryAttempts = 3
	ebpfCloseRetryDelay    = 25 * time.Millisecond
)

func retryRetainedEBPFResources() error {
	if err := ebpfcleanup.Retry(); err != nil {
		return E.Cause(err, "clean up resources retained by a previous eBPF inbound")
	}
	return nil
}

func retryRetainedEBPFResourcesOnClose() error {
	var err error
	for attempt := 0; attempt < ebpfCloseRetryAttempts; attempt++ {
		err = retryRetainedEBPFResources()
		if err == nil {
			return nil
		}
		if attempt+1 < ebpfCloseRetryAttempts {
			time.Sleep(ebpfCloseRetryDelay)
		}
	}
	return err
}
