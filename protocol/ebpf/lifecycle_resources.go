//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net/netip"
	"runtime"

	commonEBPF "github.com/CHIZI-0618/sing-ebpf"
	E "github.com/sagernet/sing/common/exceptions"
)

func (i *Inbound) prepareCgroupBackend() error {
	if err := i.reclaimCgroupBackend(); err != nil {
		return err
	}
	mapCapacity := commonEBPF.DefaultCgroupMapCapacity()
	if runtime.GOOS == "android" {
		mapCapacity = commonEBPF.CompactCgroupMapCapacity()
	}
	backend, err := commonEBPF.PrepareCgroup(commonEBPF.CgroupConfig{
		Path:         i.cgroupPath,
		EnableTCP:    i.enableTCP,
		EnableUDP:    i.enableUDP,
		EnableIPv6:   i.cgroupIPv6Enabled(),
		RedirectIPv4: i.redirectIPv4Prefix,
		RedirectIPv6: i.redirectIPv6Prefix,
		MapCapacity:  mapCapacity,
		UDPTimeout:   i.udpTimeout,
		Policy:       i.compiledPolicy,
		SelfBypass:   i.selfBypass,
	})
	if err != nil {
		return err
	}
	i.setCgroupBackend(backend)
	return nil
}

func (i *Inbound) tcBackend() *commonEBPF.TCBackend {
	i.tcDataPlaneAccess.RLock()
	defer i.tcDataPlaneAccess.RUnlock()
	if i.tcDataPlane == nil {
		return nil
	}
	return i.tcDataPlane.Backend()
}

// cgroupBackendCloser is the part of a retained backend the reclaim needs, so
// the decision can be exercised without loading one.
type cgroupBackendCloser interface {
	Close() error
	IsClosed() bool
	CgroupPath() string
}

// reclaimCgroupBackendState retries the close of a retained backend and reports
// whether it finished. It is a variable so tests can drive both outcomes.
var reclaimCgroupBackendState = func(backend cgroupBackendCloser) (bool, error) {
	closeErr := backend.Close()
	if backend.IsClosed() {
		return true, closeErr
	}
	return false, E.Errors(
		E.New("cgroup eBPF backend from a previous run is still attached to ", backend.CgroupPath()),
		closeErr,
	)
}

// reclaimCgroupBackend finishes with a backend a previous close could not,
// before a new one is prepared.
//
// Close keeps its runtime when a program could not be detached, so the handles a
// retry needs stay owned, and closeResources hands the backend back for that
// reason. Nothing retries it on its own. Two things follow from leaving it
// alone, and they are different problems.
//
// On the same cgroup, the retained handle still holds the exclusive lock
// PrepareCgroup takes, so preparing a replacement fails at the lock and reports
// the cgroup as belonging to someone else. Nothing is overwritten there, because
// the assignment only happens once PrepareCgroup has succeeded; the start simply
// cannot proceed. On a different cgroup, PrepareCgroup does succeed and the
// assignment then replaces the retained backend, which is where a reference is
// genuinely dropped.
//
// Retrying here covers both: starting up is when the lifecycle is available
// again, and this is the same close it already performs. A backend that still
// will not close is handed back rather than dropped, and the error says what is
// actually wrong instead of letting the lock failure report it as somebody
// else's cgroup.
func (i *Inbound) reclaimCgroupBackend() error {
	retained := i.takeCgroupBackend()
	if retained == nil {
		return nil
	}
	reclaimed, err := reclaimCgroupBackendState(retained)
	if !reclaimed {
		i.setCgroupBackend(retained)
	}
	return err
}

func (i *Inbound) cgroupBackendInstance() *commonEBPF.CgroupBackend {
	i.cgroupBackendAccess.RLock()
	defer i.cgroupBackendAccess.RUnlock()
	return i.cgroupBackend
}

func (i *Inbound) setCgroupBackend(backend *commonEBPF.CgroupBackend) {
	i.cgroupBackendAccess.Lock()
	i.cgroupBackend = backend
	i.cgroupBackendAccess.Unlock()
}

func (i *Inbound) takeCgroupBackend() *commonEBPF.CgroupBackend {
	i.cgroupBackendAccess.Lock()
	backend := i.cgroupBackend
	i.cgroupBackend = nil
	i.cgroupBackendAccess.Unlock()
	return backend
}

func (i *Inbound) isCgroupRedirectAddress(address netip.Addr) bool {
	address = address.Unmap()
	if address.Is4() {
		return i.redirectIPv4Prefix.IsValid() && i.redirectIPv4Prefix.Contains(address)
	}
	return address.Is6() && i.redirectIPv6Prefix.IsValid() && i.redirectIPv6Prefix.Contains(address)
}

// sharedRewriteInstance, setSharedRewrite, and takeSharedRewrite guard
// i.sharedRewrite the same way tcDataPlaneAccess guards i.tcDataPlane below:
// Diagnostics can be called at any time from an HTTP handler with no
// relationship to this inbound's own lifecycle, so a plain field read there
// races against closeResources' plain field write with nothing else
// coincidentally serializing the two -- confirmed with go test -race.
func (i *Inbound) sharedRewriteInstance() *sharedRewrite {
	i.sharedRewriteAccess.RLock()
	defer i.sharedRewriteAccess.RUnlock()
	return i.sharedRewrite
}

func (i *Inbound) setSharedRewrite(shared *sharedRewrite) {
	i.sharedRewriteAccess.Lock()
	i.sharedRewrite = shared
	i.sharedRewriteAccess.Unlock()
}

func (i *Inbound) takeSharedRewrite() *sharedRewrite {
	i.sharedRewriteAccess.Lock()
	shared := i.sharedRewrite
	i.sharedRewrite = nil
	i.sharedRewriteAccess.Unlock()
	return shared
}

func (i *Inbound) setTCDataPlane(dataPlane tcRuntime) {
	i.tcDataPlaneAccess.Lock()
	i.tcDataPlane = dataPlane
	i.tcDataPlaneAccess.Unlock()
}

func (i *Inbound) takeTCDataPlane() tcRuntime {
	i.tcDataPlaneAccess.Lock()
	dataPlane := i.tcDataPlane
	i.tcDataPlane = nil
	i.tcDataPlaneAccess.Unlock()
	return dataPlane
}

func (i *Inbound) tcDataPlaneInstance() tcRuntime {
	i.tcDataPlaneAccess.RLock()
	defer i.tcDataPlaneAccess.RUnlock()
	return i.tcDataPlane
}

func (i *Inbound) reconcileTCDataPlane(localInterface string, sharedInterfaces []string, hostAddresses []netip.Addr) error {
	i.tcDataPlaneAccess.RLock()
	defer i.tcDataPlaneAccess.RUnlock()
	if i.tcDataPlane == nil {
		return nil
	}
	return i.tcDataPlane.Reconcile(localInterface, sharedInterfaces, hostAddresses)
}

// Keep the owner reachable after both normal shutdown and startup cleanup.
func (i *Inbound) closeTakenTCDataPlane(dataPlane tcRuntime) error {
	if dataPlane == nil {
		return nil
	}
	err := dataPlane.Close()
	if !dataPlane.IsClosed() {
		i.setTCDataPlane(dataPlane)
		if err == nil {
			err = E.New("TC eBPF data plane remained open after close")
		}
	}
	return err
}

func (i *Inbound) closeTCDataPlane() error {
	return i.closeTakenTCDataPlane(i.takeTCDataPlane())
}
