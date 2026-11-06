//go:build with_ebpf && (linux || android)

package ebpf

import (
	"github.com/sagernet/sing-box/internal/ebpfcleanup"
	E "github.com/sagernet/sing/common/exceptions"
)

// The process-level registry is also retried by every Box before startup and
// during final cleanup. Keeping the direct inbound retry preserves the same
// guarantee for callers that drive an inbound lifecycle without a Box.
func retainForRetry(inbound *Inbound) {
	ebpfcleanup.Retain(inbound.retainedCleanupEntry())
}

func releaseRetained(inbound *Inbound) {
	ebpfcleanup.Release(inbound.retainedCleanupEntry())
}

func (i *Inbound) retainedCleanupEntry() *ebpfcleanup.Entry {
	i.retainedCleanupOnce.Do(func() {
		i.retainedCleanup = ebpfcleanup.New(i.Close)
	})
	return i.retainedCleanup
}

func retryRetainedInbounds() error {
	if err := ebpfcleanup.Retry(); err != nil {
		return E.Cause(err, "clean up resources retained by a previous eBPF inbound")
	}
	return nil
}

// retainsResources reports whether a failed cleanup kept resources that a
// later Close must release.
func (i *Inbound) retainsResources() bool {
	i.tcNamespaceAccess.RLock()
	tcNamespace := i.tcNamespace
	i.tcNamespaceAccess.RUnlock()
	return i.tcBackend() != nil || i.cgroupBackendInstance() != nil || i.sharedRewriteInstance() != nil ||
		tcNamespace != nil || i.localRoutes != nil || i.selfBypass != nil ||
		i.processTracker != nil || i.processTrackerRollback != nil
}
