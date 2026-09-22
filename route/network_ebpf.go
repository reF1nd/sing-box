//go:build with_ebpf && (linux || android)

package route

import (
	"sync/atomic"

	E "github.com/sagernet/sing/common/exceptions"

	commonEBPF "github.com/CHIZI-0618/sing-ebpf"
)

type ebpfSelfBypassState struct {
	tracker atomic.Pointer[commonEBPF.SelfBypass]
}

func (r *NetworkManager) SetEBPFSelfBypass(tracker *commonEBPF.SelfBypass) error {
	if tracker == nil {
		return E.New("invalid eBPF self-bypass tracker")
	}
	if current := r.ebpfSelfBypass.tracker.Load(); current != nil && current != tracker {
		return E.New("eBPF self-bypass tracker is already configured")
	}
	r.ebpfSelfBypass.tracker.Store(tracker)
	return nil
}

func (r *NetworkManager) EBPFSelfBypass() *commonEBPF.SelfBypass {
	return r.ebpfSelfBypass.tracker.Load()
}

func (r *NetworkManager) ClearEBPFSelfBypass(tracker *commonEBPF.SelfBypass) {
	r.ebpfSelfBypass.tracker.CompareAndSwap(tracker, nil)
}
