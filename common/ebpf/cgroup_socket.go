//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"net/netip"
	"time"
	"unsafe"

	E "github.com/sagernet/sing/common/exceptions"

	CiliumEBPF "github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

const (
	mapLookupAndDeleteUnknown int32 = iota
	mapLookupAndDeleteSupported
	mapLookupAndDeleteUnsupported
)

func (b *CgroupBackend) RegisterProtectedSocket(cookie uint64) error {
	if b == nil {
		return errBackendClosed
	}
	if cookie == 0 {
		return E.New("invalid socket cookie")
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil || b.socketBypassMapFD < 0 {
		return errBackendClosed
	}
	value := uint8(1)
	if err := updateMap(b.socketBypassMapFD, unsafe.Pointer(&cookie), unsafe.Pointer(&value)); err != nil {
		return E.Cause(err, "register eBPF bypass socket")
	}
	return nil
}

func (b *CgroupBackend) LookupOriginal(protocol uint8, listenerDestination netip.AddrPort) (OriginalDestination, error) {
	return b.lookupOriginal(protocol, listenerDestination, false)
}

func (b *CgroupBackend) TakeOriginal(protocol uint8, listenerDestination netip.AddrPort) (OriginalDestination, error) {
	return b.lookupOriginal(protocol, listenerDestination, true)
}

func (b *CgroupBackend) lookupOriginal(
	protocol uint8,
	listenerDestination netip.AddrPort,
	deleteAfterLookup bool,
) (OriginalDestination, error) {
	if b == nil {
		return OriginalDestination{}, errBackendClosed
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return OriginalDestination{}, errBackendClosed
	}
	key, err := makeListenerLookupKey(protocol, listenerDestination)
	if err != nil {
		return OriginalDestination{}, err
	}
	var original originalDestinationValue
	redirectMap, err := b.redirectMap(protocol)
	if err != nil {
		return OriginalDestination{}, err
	}
	if deleteAfterLookup {
		err = b.takeMapElement(redirectMap, unsafe.Pointer(&key), unsafe.Pointer(&original))
	} else {
		err = lookupMap(redirectMap, unsafe.Pointer(&key), unsafe.Pointer(&original))
	}
	if err != nil {
		return OriginalDestination{}, E.Cause(err, "lookup original destination")
	}
	return originalDestinationFromValue(original)
}

func (b *CgroupBackend) RecoverUDPOriginal(listenerDestination netip.AddrPort) (OriginalDestination, error) {
	if b == nil {
		return OriginalDestination{}, errBackendClosed
	}
	key, err := makeListenerLookupKey(ProtocolUDP, listenerDestination)
	if err != nil {
		return OriginalDestination{}, err
	}
	b.udpRecoveryAccess.Lock()
	defer b.udpRecoveryAccess.Unlock()
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return OriginalDestination{}, errBackendClosed
	}
	var original originalDestinationValue
	consumed, err := b.takeUDPRecoveryElement(&key, &original)
	if err != nil {
		return OriginalDestination{}, E.Cause(err, "lookup recoverable UDP original destination")
	}
	recoveryOriginal := original
	if err = updateMapWithFlags(
		b.udpRedirectMapFD,
		unsafe.Pointer(&key),
		unsafe.Pointer(&original),
		bpfNoExist,
	); err != nil {
		if !errors.Is(err, unix.EEXIST) {
			return OriginalDestination{}, b.rollbackConsumedUDPRecovery(
				&key,
				&recoveryOriginal,
				consumed,
				E.Cause(err, "restore UDP original destination"),
			)
		}
		var existing originalDestinationValue
		if err = lookupMap(b.udpRedirectMapFD, unsafe.Pointer(&key), unsafe.Pointer(&existing)); err != nil {
			return OriginalDestination{}, b.rollbackConsumedUDPRecovery(
				&key,
				&recoveryOriginal,
				consumed,
				E.Cause(err, "lookup concurrently restored UDP original destination"),
			)
		}
		original = existing
	}
	return originalDestinationFromValue(original)
}

func (b *CgroupBackend) takeUDPRecoveryElement(
	key *listenerLookupKey,
	original *originalDestinationValue,
) (bool, error) {
	if b.udpRecoveryConsumeMode.Load() != mapLookupAndDeleteUnsupported {
		err := lookupAndDeleteMap(
			b.udpRecoveryMapFD,
			unsafe.Pointer(key),
			unsafe.Pointer(original),
		)
		if err == nil || errors.Is(err, unix.ENOENT) {
			b.udpRecoveryConsumeMode.Store(mapLookupAndDeleteSupported)
			return err == nil, err
		}
		if !mapLookupAndDeleteUnavailable(err) {
			return false, err
		}
		b.udpRecoveryConsumeMode.Store(mapLookupAndDeleteUnsupported)
	}
	// A lookup+delete fallback could remove a newer kernel update between the
	// two syscalls. Preserve the LRU entry on kernels without atomic support.
	err := lookupMap(
		b.udpRecoveryMapFD,
		unsafe.Pointer(key),
		unsafe.Pointer(original),
	)
	return false, err
}

func (b *CgroupBackend) rollbackConsumedUDPRecovery(
	key *listenerLookupKey,
	original *originalDestinationValue,
	consumed bool,
	recoveryErr error,
) error {
	if !consumed {
		return recoveryErr
	}
	err := updateMapWithFlags(
		b.udpRecoveryMapFD,
		unsafe.Pointer(key),
		unsafe.Pointer(original),
		bpfNoExist,
	)
	if err == nil || errors.Is(err, unix.EEXIST) {
		return recoveryErr
	}
	return E.Errors(recoveryErr, E.Cause(err, "restore consumed UDP recovery state"))
}

func (b *CgroupBackend) RecoverConnectedUDPOriginal(listenerDestination netip.AddrPort) (OriginalDestination, error) {
	if b == nil {
		return OriginalDestination{}, errBackendClosed
	}
	listener, err := makeListenerLookupKey(ProtocolUDP, listenerDestination)
	if err != nil {
		return OriginalDestination{}, err
	}
	b.udpRecoveryAccess.Lock()
	defer b.udpRecoveryAccess.Unlock()
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return OriginalDestination{}, errBackendClosed
	}
	if b.runtime.socket_release_supported {
		return OriginalDestination{}, E.Cause(unix.ENOENT, "connected UDP LRU recovery is disabled")
	}
	tokenMap := b.runtime.maps["cgroup_udp_token"]
	if tokenMap == nil {
		return OriginalDestination{}, E.New("connected UDP token map is unavailable")
	}
	cookie, err := b.findConnectedUDPToken(tokenMap, listener)
	if err != nil {
		return OriginalDestination{}, E.Cause(err, "scan connected UDP token state")
	}
	if cookie == 0 {
		return OriginalDestination{}, E.Cause(unix.ENOENT, "find connected UDP token state")
	}
	var verifiedToken listenerLookupKey
	if err = lookupMap(
		b.runtime.udp_token_map_fd,
		unsafe.Pointer(&cookie),
		unsafe.Pointer(&verifiedToken),
	); err != nil {
		return OriginalDestination{}, E.Cause(err, "verify connected UDP token state")
	}
	if verifiedToken != listener {
		return OriginalDestination{}, E.Cause(unix.ENOENT, "connected UDP token changed during recovery")
	}
	peerKey := udpPeerKey{SocketCookie: cookie}
	var peer udpPeerValue
	if err = lookupMap(
		b.runtime.udp_peer_map_fd,
		unsafe.Pointer(&peerKey),
		unsafe.Pointer(&peer),
	); err != nil {
		return OriginalDestination{}, E.Cause(err, "lookup connected UDP peer state")
	}
	original, err := originalDestinationFromUDPPeer(cookie, peer)
	if err != nil {
		return OriginalDestination{}, E.Cause(err, "validate connected UDP peer state")
	}
	if original.Family != listener.Family {
		return OriginalDestination{}, E.New(
			"connected UDP token and peer family mismatch: token=", listener.Family,
			", peer=", original.Family,
		)
	}
	if err = lookupMap(
		b.runtime.udp_token_map_fd,
		unsafe.Pointer(&cookie),
		unsafe.Pointer(&verifiedToken),
	); err != nil {
		return OriginalDestination{}, E.Cause(err, "revalidate connected UDP token state")
	}
	if verifiedToken != listener {
		return OriginalDestination{}, E.Cause(unix.ENOENT, "connected UDP token changed during recovery")
	}
	err = updateMapWithFlags(
		b.udpRedirectMapFD,
		unsafe.Pointer(&listener),
		unsafe.Pointer(&original),
		bpfNoExist,
	)
	if errors.Is(err, unix.EEXIST) {
		var existing originalDestinationValue
		if lookupErr := lookupMap(
			b.udpRedirectMapFD,
			unsafe.Pointer(&listener),
			unsafe.Pointer(&existing),
		); lookupErr != nil {
			return OriginalDestination{}, E.Cause(lookupErr, "verify concurrently restored connected UDP redirect")
		}
		if existing != original {
			return OriginalDestination{}, E.New("connected UDP redirect token was concurrently claimed")
		}
		err = nil
	}
	if err != nil {
		return OriginalDestination{}, E.Cause(err, "restore connected UDP redirect state")
	}
	return originalDestinationFromValue(original)
}

func (b *CgroupBackend) findConnectedUDPToken(
	tokenMap *CiliumEBPF.Map,
	listener listenerLookupKey,
) (uint64, error) {
	// Connected UDP recovery is a cold path. Batch lookup avoids one syscall
	// per token on kernels that implement BPF_MAP_LOOKUP_BATCH, while the
	// support state keeps vendor/old kernels on the proven iterator path.
	if b.connectedUDPTokenLookupSupport.mode.Load() != mapBatchUnsupported {
		batchCapacity := min(uint32(mapBatchMaxEntries), b.mapCapacity.UDPRedirect)
		if cap(b.connectedUDPTokenKeys) < int(batchCapacity) {
			b.connectedUDPTokenKeys = make([]uint64, batchCapacity)
			b.connectedUDPTokenValues = make([]listenerLookupKey, batchCapacity)
		} else {
			b.connectedUDPTokenKeys = b.connectedUDPTokenKeys[:batchCapacity]
			b.connectedUDPTokenValues = b.connectedUDPTokenValues[:batchCapacity]
		}
		var cursor CiliumEBPF.MapBatchCursor
		var scanned uint32
		for scanned < b.mapCapacity.UDPRedirect {
			batchSize := min(batchCapacity, b.mapCapacity.UDPRedirect-scanned)
			countValue, batchErr := tokenMap.BatchLookup(
				&cursor,
				b.connectedUDPTokenKeys[:batchSize],
				b.connectedUDPTokenValues[:batchSize],
				nil,
			)
			count := uint32(countValue)
			for index := range count {
				if b.connectedUDPTokenValues[index] == listener {
					b.connectedUDPTokenLookupSupport.mode.CompareAndSwap(mapBatchUnknown, mapBatchSupported)
					return b.connectedUDPTokenKeys[index], nil
				}
			}
			scanned += count
			if errors.Is(batchErr, CiliumEBPF.ErrKeyNotExist) {
				b.connectedUDPTokenLookupSupport.mode.CompareAndSwap(mapBatchUnknown, mapBatchSupported)
				return 0, unix.ENOENT
			}
			if batchErr != nil {
				if !mapBatchUnsupportedError(batchErr) {
					return 0, batchErr
				}
				b.connectedUDPTokenLookupSupport.mode.Store(mapBatchUnsupported)
				break
			}
			if count == 0 {
				return 0, unix.EIO
			}
			b.connectedUDPTokenLookupSupport.mode.CompareAndSwap(mapBatchUnknown, mapBatchSupported)
		}
		if b.connectedUDPTokenLookupSupport.mode.Load() == mapBatchSupported {
			return 0, unix.ENOENT
		}
	}
	var (
		cookie       uint64
		currentToken listenerLookupKey
		scanned      uint32
	)
	iterator := tokenMap.Iterate()
	for iterator.Next(&cookie, &currentToken) {
		scanned++
		if currentToken == listener {
			return cookie, nil
		}
		if scanned >= b.mapCapacity.UDPRedirect {
			break
		}
	}
	if err := iterator.Err(); err != nil {
		return 0, err
	}
	return 0, unix.ENOENT
}

func (b *CgroupBackend) ReserveUDPReplyRedirect(
	destination netip.AddrPort,
	listenerPort uint16,
) (netip.Addr, error) {
	if b == nil {
		return netip.Addr{}, errBackendClosed
	}
	if !destination.IsValid() || destination.Port() == 0 || destination.Addr().IsUnspecified() {
		return netip.Addr{}, E.New("invalid UDP reply source: ", destination)
	}
	if listenerPort == 0 {
		return netip.Addr{}, E.New("invalid UDP redirect listener port")
	}
	var original originalDestinationValue
	original.Protocol = ProtocolUDP
	original.Port = destination.Port()
	if err := encodeAddress(&original.Family, &original.Addr, destination.Addr()); err != nil {
		return netip.Addr{}, E.Cause(err, "encode UDP reply source")
	}

	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return netip.Addr{}, errBackendClosed
	}
	prefix := b.redirectIPv4
	if destination.Addr().Is6() {
		prefix = b.redirectIPv6
	}
	if !prefix.IsValid() {
		return netip.Addr{}, E.New("UDP reply source address family is not enabled: ", destination)
	}
	for attempt := 0; attempt < userspaceReplyTokenAttempts; {
		sequence := b.udpReplyTokenSequence.Add(1)
		token, valid := userspaceReplyToken(prefix, sequence)
		if !valid {
			continue
		}
		attempt++
		key, err := makeListenerLookupKey(ProtocolUDP, netip.AddrPortFrom(token, listenerPort))
		if err != nil {
			return netip.Addr{}, err
		}
		err = updateMapWithFlags(
			b.udpRedirectMapFD,
			unsafe.Pointer(&key),
			unsafe.Pointer(&original),
			bpfNoExist,
		)
		if err == nil {
			return token, nil
		}
		if !errors.Is(err, unix.EEXIST) {
			return netip.Addr{}, E.Cause(err, "reserve UDP reply redirect")
		}
	}
	return netip.Addr{}, E.New("reserve UDP reply redirect: token attempts exhausted")
}

func (b *CgroupBackend) takeMapElement(mapFD int, key unsafe.Pointer, value unsafe.Pointer) error {
	if b.lookupAndDeleteMode.Load() != mapLookupAndDeleteUnsupported {
		err := lookupAndDeleteMap(mapFD, key, value)
		if err == nil || errors.Is(err, unix.ENOENT) {
			b.lookupAndDeleteMode.Store(mapLookupAndDeleteSupported)
			return err
		}
		if !mapLookupAndDeleteUnavailable(err) {
			return err
		}
		b.lookupAndDeleteMode.Store(mapLookupAndDeleteUnsupported)
	}
	if err := lookupMap(mapFD, key, value); err != nil {
		return err
	}
	err := deleteMap(mapFD, key)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	return err
}

func mapLookupAndDeleteUnavailable(err error) bool {
	return errors.Is(err, unix.ENOSYS) ||
		errors.Is(err, unix.EINVAL) ||
		errors.Is(err, unix.EOPNOTSUPP) ||
		errors.Is(err, linuxErrnoNotSupported)
}

type tcpRedirectEntry struct {
	key   listenerLookupKey
	value originalDestinationValue
}

func (b *CgroupBackend) SweepStaleTCPRedirects(
	maxAge time.Duration,
	fallbackBudget uint32,
) (CgroupTCPRedirectSweepResult, error) {
	if b == nil {
		return CgroupTCPRedirectSweepResult{}, errBackendClosed
	}
	if maxAge <= 0 || fallbackBudget == 0 {
		return CgroupTCPRedirectSweepResult{}, unix.EINVAL
	}
	b.tcpSweepAccess.Lock()
	defer b.tcpSweepAccess.Unlock()

	var now unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &now); err != nil {
		return CgroupTCPRedirectSweepResult{}, err
	}
	nowNS := uint64(now.Sec)*uint64(time.Second) + uint64(now.Nsec)
	maxAgeNS := uint64(maxAge)
	if nowNS <= maxAgeNS {
		return CgroupTCPRedirectSweepResult{
			Complete: true,
		}, nil
	}
	staleBefore := nowNS - maxAgeNS

	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return CgroupTCPRedirectSweepResult{}, errBackendClosed
	}
	b.tcpSweepCandidates = b.tcpSweepCandidates[:0]
	b.tcpSweepDeleteKeys = b.tcpSweepDeleteKeys[:0]
	scan, err := b.tcpSweepScratch.scan(
		b.runtime.maps["cgroup_tcp_redirect"],
		b.mapCapacity.TCPRedirect,
		fallbackBudget,
		func(key listenerLookupKey, value originalDestinationValue) {
			if value.CreatedAtNS != 0 && value.CreatedAtNS <= staleBefore {
				b.tcpSweepCandidates = append(b.tcpSweepCandidates, tcpRedirectEntry{key: key, value: value})
			}
		},
	)
	if err != nil {
		return CgroupTCPRedirectSweepResult{}, err
	}
	result := CgroupTCPRedirectSweepResult{
		Scanned:  scan.Scanned,
		Complete: scan.Complete,
	}
	var sweepErr error
	for _, entry := range b.tcpSweepCandidates {
		var current originalDestinationValue
		if err = lookupMap(b.tcpRedirectMapFD, unsafe.Pointer(&entry.key), unsafe.Pointer(&current)); err != nil {
			if !errors.Is(err, unix.ENOENT) {
				sweepErr = E.Errors(sweepErr, err)
			}
			continue
		}
		if current != entry.value {
			continue
		}
		b.tcpSweepDeleteKeys = append(b.tcpSweepDeleteKeys, entry.key)
	}
	removed, deleteErr := deleteMapBatchIfExists(
		b.runtime.maps["cgroup_tcp_redirect"],
		b.tcpSweepDeleteKeys,
		&b.tcpSweepDeleteSupport,
	)
	result.Removed = removed
	if deleteErr != nil {
		sweepErr = E.Errors(sweepErr, deleteErr)
	}
	return result, sweepErr
}

func (b *CgroupBackend) DeleteRedirect(protocol uint8, listenerDestination netip.AddrPort) error {
	if b == nil {
		return errBackendClosed
	}
	key, err := makeListenerLookupKey(protocol, listenerDestination)
	if err != nil {
		return err
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return errBackendClosed
	}
	redirectMap, err := b.redirectMap(protocol)
	if err != nil {
		return err
	}
	if protocol == ProtocolUDP && b.udpFlowMapFD >= 0 {
		var original originalDestinationValue
		lookupErr := lookupMap(redirectMap, unsafe.Pointer(&key), unsafe.Pointer(&original))
		if lookupErr == nil {
			if recoveryErr := updateMap(
				b.udpRecoveryMapFD,
				unsafe.Pointer(&key),
				unsafe.Pointer(&original),
			); recoveryErr != nil {
				return E.Cause(recoveryErr, "retain recoverable UDP original destination")
			}
		}
		if lookupErr == nil && original.SocketCookie != 0 {
			flowKey := makeUDPFlowKey(original)
			flowErr := deleteMap(b.udpFlowMapFD, unsafe.Pointer(&flowKey))
			if flowErr != nil && !errors.Is(flowErr, unix.ENOENT) {
				return E.Cause(flowErr, "delete UDP flow cache")
			}
		} else if lookupErr != nil && !errors.Is(lookupErr, unix.ENOENT) {
			return E.Cause(lookupErr, "lookup UDP flow cache key")
		}
	}
	err = deleteMap(redirectMap, unsafe.Pointer(&key))
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return E.Cause(err, "delete redirect mapping")
	}
	return nil
}

func (b *CgroupBackend) redirectMap(protocol uint8) (int, error) {
	switch protocol {
	case ProtocolTCP:
		return b.tcpRedirectMapFD, nil
	case ProtocolUDP:
		return b.udpRedirectMapFD, nil
	default:
		return -1, E.New("unsupported eBPF redirect protocol: ", protocol)
	}
}

func (b *CgroupBackend) TCPRedirectReservationFailures() (uint64, error) {
	if b == nil {
		return 0, errBackendClosed
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return 0, errBackendClosed
	}
	var key uint32
	var failures uint64
	if err := lookupMap(b.statsMapFD, unsafe.Pointer(&key), unsafe.Pointer(&failures)); err != nil {
		return 0, err
	}
	return failures, nil
}
