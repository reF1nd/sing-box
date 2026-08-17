//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"net/netip"
	"time"
	"unsafe"

	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/sys/unix"
)

func (b *SharedNetworkBackend) LookupOriginal(
	protocol uint8,
	client netip.AddrPort,
	tokenDestination netip.AddrPort,
) (OriginalDestination, error) {
	original, _, err := b.lookupFlow(protocol, client, tokenDestination, false)
	return original, err
}

func (b *SharedNetworkBackend) LookupFlow(
	protocol uint8,
	client netip.AddrPort,
	tokenDestination netip.AddrPort,
) (OriginalDestination, *SharedNetworkFlowHandle, error) {
	return b.lookupFlow(protocol, client, tokenDestination, true)
}

func (b *SharedNetworkBackend) lookupFlow(
	protocol uint8,
	client netip.AddrPort,
	tokenDestination netip.AddrPort,
	retain bool,
) (OriginalDestination, *SharedNetworkFlowHandle, error) {
	if b == nil {
		return OriginalDestination{}, nil, errBackendClosed
	}
	key, err := makeSharedNetworkListenerKey(protocol, client, tokenDestination)
	if err != nil {
		return OriginalDestination{}, nil, err
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return OriginalDestination{}, nil, errBackendClosed
	}
	if retain {
		b.flowAccess.Lock()
		defer b.flowAccess.Unlock()
	}
	var value sharedNetworkOriginalValue
	if err = lookupMap(
		int(b.runtime.listener_map_fd),
		unsafe.Pointer(&key),
		unsafe.Pointer(&value),
	); err != nil {
		return OriginalDestination{}, nil, E.Cause(err, "lookup shared-network original destination")
	}
	address, err := sharedNetworkOriginalAddress(value)
	if err != nil {
		return OriginalDestination{}, nil, err
	}
	flow := makeSharedNetworkFlowHandle(key, value)
	if retain {
		b.retainFlowLocked(flow)
	}
	return OriginalDestination{
		Destination: netip.AddrPortFrom(address, value.Port),
		SourceMAC:   sharedNetworkOriginalMAC(value),
	}, &flow, nil
}

func (b *SharedNetworkBackend) ReleaseFlow(flow *SharedNetworkFlowHandle) error {
	if b == nil || flow == nil {
		return nil
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return nil
	}
	b.flowAccess.Lock()
	defer b.flowAccess.Unlock()
	if !b.releaseFlowReferenceLocked(*flow) {
		return nil
	}
	return E.Errors(
		deleteMapIfExists(int(b.runtime.listener_map_fd), unsafe.Pointer(&flow.listenerKey)),
		deleteMapIfExists(int(b.runtime.reply_map_fd), unsafe.Pointer(&flow.replyKey)),
		deleteMapIfExists(int(b.runtime.original_to_token_map_fd), unsafe.Pointer(&flow.originalKey)),
	)
}

func (b *SharedNetworkBackend) retainFlowLocked(flow SharedNetworkFlowHandle) {
	if b.flowReferences == nil {
		b.flowReferences = make(map[SharedNetworkFlowHandle]uint32)
	}
	b.flowReferences[flow]++
}

func (b *SharedNetworkBackend) releaseFlowReferenceLocked(flow SharedNetworkFlowHandle) bool {
	references := b.flowReferences[flow]
	if references == 0 {
		return false
	}
	if references > 1 {
		b.flowReferences[flow] = references - 1
		return false
	}
	delete(b.flowReferences, flow)
	return true
}

type sharedNetworkFlowEntry struct {
	key   sharedNetworkOriginalKey
	value sharedNetworkTokenValue
}

func (b *SharedNetworkBackend) SweepOrphanedFlows(
	maxIdle time.Duration,
	fallbackBudget uint32,
) (SharedNetworkFlowSweepResult, error) {
	if b == nil {
		return SharedNetworkFlowSweepResult{}, errBackendClosed
	}
	if maxIdle <= 0 || fallbackBudget == 0 {
		return SharedNetworkFlowSweepResult{}, unix.EINVAL
	}
	b.flowSweepAccess.Lock()
	defer b.flowSweepAccess.Unlock()

	var now unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &now); err != nil {
		return SharedNetworkFlowSweepResult{}, err
	}
	nowNS := uint64(now.Sec)*uint64(time.Second) + uint64(now.Nsec)
	maxIdleNS := uint64(maxIdle)
	if nowNS <= maxIdleNS {
		return SharedNetworkFlowSweepResult{
			Usage:    MapUsage{Capacity: b.mapCapacity.Proxy},
			Complete: true,
		}, nil
	}
	staleBefore := nowNS - maxIdleNS

	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return SharedNetworkFlowSweepResult{}, errBackendClosed
	}
	mapFD := int(b.runtime.original_to_token_map_fd)
	b.flowSweepCandidates = b.flowSweepCandidates[:0]
	scan, err := b.flowSweepScratch.scan(
		mapFD,
		b.mapCapacity.Proxy,
		fallbackBudget,
		func(key sharedNetworkOriginalKey, value sharedNetworkTokenValue) {
			if value.LastSeenNS != 0 && value.LastSeenNS <= staleBefore {
				b.flowSweepCandidates = append(
					b.flowSweepCandidates,
					sharedNetworkFlowEntry{key: key, value: value},
				)
			}
		},
	)
	if err != nil {
		return SharedNetworkFlowSweepResult{}, err
	}
	result := SharedNetworkFlowSweepResult{
		Scanned:  scan.Scanned,
		Usage:    MapUsage{Capacity: b.mapCapacity.Proxy},
		Complete: scan.Complete,
	}
	if b.proxyUsageKnown.Load() {
		result.Usage.Entries = b.proxyUsage.Load()
	}
	var sweepErr error
	for _, entry := range b.flowSweepCandidates {
		removed, retained, removeErr := b.removeOrphanedFlowCandidate(mapFD, entry)
		if retained {
			result.Retained++
		}
		if removeErr != nil {
			sweepErr = E.Errors(sweepErr, removeErr)
			continue
		}
		if removed {
			result.Removed++
		}
	}
	b.flowSweepRemoved += result.Removed
	if result.Complete {
		result.Usage.Entries = scan.Entries
		if b.flowSweepRemoved >= result.Usage.Entries {
			result.Usage.Entries = 0
		} else {
			result.Usage.Entries -= b.flowSweepRemoved
		}
		b.flowSweepRemoved = 0
		b.proxyUsage.Store(result.Usage.Entries)
		b.proxyUsageKnown.Store(true)
	}
	return result, sweepErr
}

func (b *SharedNetworkBackend) removeOrphanedFlowCandidate(
	mapFD int,
	entry sharedNetworkFlowEntry,
) (removed bool, retained bool, err error) {
	flow := makeSharedNetworkFlowHandleFromOriginal(
		entry.key,
		entry.value.TokenAddr,
		b.control.ListenerPort,
	)
	b.flowAccess.Lock()
	defer b.flowAccess.Unlock()
	if b.flowReferences[flow] > 0 {
		return false, true, nil
	}
	var current sharedNetworkTokenValue
	if err = lookupMap(mapFD, unsafe.Pointer(&entry.key), unsafe.Pointer(&current)); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return false, false, nil
		}
		return false, false, err
	}
	if current != entry.value {
		return false, false, nil
	}
	err = E.Errors(
		deleteMapIfExists(int(b.runtime.listener_map_fd), unsafe.Pointer(&flow.listenerKey)),
		deleteMapIfExists(int(b.runtime.reply_map_fd), unsafe.Pointer(&flow.replyKey)),
		deleteMapIfExists(mapFD, unsafe.Pointer(&flow.originalKey)),
	)
	return err == nil, false, err
}

func (b *SharedNetworkBackend) ProxyMapUsage() (MapUsage, error) {
	if b == nil {
		return MapUsage{}, errBackendClosed
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return MapUsage{}, errBackendClosed
	}
	usage := MapUsage{
		Entries:  b.proxyUsage.Load(),
		Capacity: b.mapCapacity.Proxy,
	}
	if !b.proxyUsageKnown.Load() {
		return usage, unix.ENODATA
	}
	return usage, nil
}

func deleteMapIfExists(mapFD int, key unsafe.Pointer) error {
	err := deleteMap(mapFD, key)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	return err
}

func (b *SharedNetworkBackend) TokenReservationFailures() (uint64, error) {
	if b == nil {
		return 0, errBackendClosed
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return 0, errBackendClosed
	}
	key := uint32(sharedNetworkStatTokenReservationFailure)
	var failures uint64
	if err := lookupMap(b.statsMapFD, unsafe.Pointer(&key), unsafe.Pointer(&failures)); err != nil {
		return 0, err
	}
	return failures, nil
}
