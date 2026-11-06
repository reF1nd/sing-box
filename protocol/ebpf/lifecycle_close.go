//go:build with_ebpf && (linux || android)

package ebpf

import (
	commonEBPF "github.com/CHIZI-0618/sing-ebpf"
	E "github.com/sagernet/sing/common/exceptions"
)

func (i *Inbound) Close() error {
	// Record the inbound before releasing anything: a concurrent initialization
	// then waits for this Close instead of missing resources it retains.
	retainForRetry(i)
	i.lifecycleAccess.Lock()
	defer i.lifecycleAccess.Unlock()
	err := i.closeResources()
	if !i.retainsResources() {
		releaseRetained(i)
	}
	return err
}

func (i *Inbound) cleanupStartFailure() error {
	return i.closeResources()
}

func (i *Inbound) closeResources() error {
	monitorErr := i.stopInboundWorkers()
	sharedRewriteErr := i.closeSharedRewriteOwner()
	dataPlane := i.takeTCDataPlane()
	disableErr := error(nil)
	if dataPlane != nil {
		disableErr = dataPlane.Disable()
	}
	cgroupErr := i.closeCgroupBackendOwner()
	listenerErr, udpNATErr, udpReplySocketErr := i.closeUDPResources()
	dataPlaneErr := i.closeTakenTCDataPlane(dataPlane)
	// Failed detaches retain their owner and dependencies for the next Close.
	// In particular, removing redirect routes or self-bypass while a hook is
	// still attached can redirect traffic into a dead path or capture ourselves.
	if i.tcBackend() != nil || i.cgroupBackendInstance() != nil || i.sharedRewriteInstance() != nil {
		return E.Errors(monitorErr, sharedRewriteErr, disableErr, listenerErr, udpNATErr, udpReplySocketErr, dataPlaneErr, cgroupErr)
	}
	namespaceErr := error(nil)
	if i.tcBackend() == nil {
		i.tcNamespaceAccess.Lock()
		if i.tcNamespace != nil {
			namespaceErr = i.tcNamespace.Close()
			i.tcNamespace = nil
		}
		i.tcNamespaceAccess.Unlock()
	}
	routeErr := i.removeLocalRoutes()
	selfBypassErr := error(nil)
	if i.selfBypass != nil {
		if clearer, loaded := i.networkManager.(interface {
			ClearEBPFSelfBypass(*commonEBPF.SelfBypass)
		}); loaded {
			clearer.ClearEBPFSelfBypass(i.selfBypass)
		}
		selfBypassErr = i.selfBypass.Close()
		if i.selfBypass.IsClosed() {
			i.selfBypass = nil
		} else if selfBypassErr == nil {
			selfBypassErr = E.New("eBPF self-bypass remained open after close")
		}
	}
	processTrackerErr := error(nil)
	if i.processTracker != nil {
		i.processTracker, processTrackerErr = closeProcessTrackerOwner(i.processTracker)
	}
	processTrackerRollbackErr := error(nil)
	if i.processTrackerRollback != nil {
		i.processTrackerRollback, processTrackerRollbackErr = closeProcessTrackerOwner(i.processTrackerRollback)
	}
	return E.Errors(monitorErr, sharedRewriteErr, disableErr, listenerErr, udpNATErr, udpReplySocketErr, dataPlaneErr, namespaceErr, cgroupErr, routeErr, processTrackerErr, processTrackerRollbackErr, selfBypassErr)
}

func (i *Inbound) stopInboundWorkers() error {
	i.stopTCAssignmentJanitor()
	monitorErr := i.stopTCInterfaceMonitor()
	i.stopBypassRuleSets()
	return monitorErr
}

func (i *Inbound) closeSharedRewriteOwner() error {
	shared := i.takeSharedRewrite()
	if shared == nil {
		return nil
	}
	closeErr := shared.Close()
	if !shared.IsClosed() {
		i.setSharedRewrite(shared)
		if closeErr == nil {
			closeErr = E.New("shared packet-rewrite runtime remained open after close")
		}
	}
	return closeErr
}

func (i *Inbound) closeCgroupBackendOwner() error {
	backend := i.takeCgroupBackend()
	if backend == nil {
		return nil
	}
	i.stopCgroupRecoveryScheduler()
	closeErr := backend.Close()
	i.cgroupReleaseWait.Wait()
	// A legacy cgroup attachment belongs to the cgroup rather than the program
	// handle. Keep the backend owner when detach failed so a later Close can
	// retry it instead of leaving an attached program with no owner.
	if !backend.IsClosed() {
		i.setCgroupBackend(backend)
		if closeErr == nil {
			closeErr = E.New("cgroup eBPF backend remained open after close")
		}
	}
	return closeErr
}

func (i *Inbound) closeUDPResources() (listenerErr, udpNATErr, udpReplySocketErr error) {
	listenerErr = i.closeListeners()
	udpNATErr = i.udpNat.Close()
	i.udpReplySockets.stopSweeper()
	udpReplySocketErr = i.udpReplySockets.close()
	return
}

func closeProcessTrackerOwner(tracker processTrackerOwner) (processTrackerOwner, error) {
	if tracker == nil {
		return nil, nil
	}
	closeErr := tracker.Close()
	if tracker.IsClosed() {
		return nil, closeErr
	}
	if closeErr == nil {
		closeErr = E.New("eBPF process tracker remained open after close")
	}
	return tracker, closeErr
}
