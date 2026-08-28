//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"runtime"
	"sync/atomic"
	"syscall"
	"unsafe"

	E "github.com/sagernet/sing/common/exceptions"

	CiliumEBPF "github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

const (
	bpfMapLookupElem          = 1
	bpfMapUpdateElem          = 2
	bpfMapDeleteElem          = 3
	bpfMapGetNextKey          = 4
	bpfMapLookupAndDeleteElem = 21
	bpfNoExist                = 1

	mapBatchUnknown int32 = iota
	mapBatchSupported
	mapBatchUnsupported
	mapBatchMaxEntries = 1024

	// ENOTSUPP is an internal Linux errno that some Android kernels return
	// directly when a BPF command is unavailable.
	linuxErrnoNotSupported syscall.Errno = 524
)

type mapElementAttr struct {
	MapFD uint32
	_     uint32
	Key   uint64
	Value uint64
	Flags uint64
}

type mapBatchSupport struct {
	mode atomic.Int32
}

// Per-flow lookups use typed raw-FD syscalls to avoid reflection and allocation
// in the redirect hot path. Map creation, object loading, and attachment remain
// owned by cilium/ebpf; batch operations retain a per-entry fallback for vendor
// kernels that expose the commands but reject them at runtime.

func lookupMap(mapFD int, key unsafe.Pointer, value unsafe.Pointer) error {
	return mapOperation(bpfMapLookupElem, mapFD, key, value, 0)
}

func lookupAndDeleteMap(mapFD int, key unsafe.Pointer, value unsafe.Pointer) error {
	return mapOperation(bpfMapLookupAndDeleteElem, mapFD, key, value, 0)
}

func updateMap(mapFD int, key unsafe.Pointer, value unsafe.Pointer) error {
	return updateMapWithFlags(mapFD, key, value, 0)
}

func updateMapWithFlags(mapFD int, key unsafe.Pointer, value unsafe.Pointer, flags uint64) error {
	return mapOperation(bpfMapUpdateElem, mapFD, key, value, flags)
}

func deleteMap(mapFD int, key unsafe.Pointer) error {
	return mapOperation(bpfMapDeleteElem, mapFD, key, nil, 0)
}

func (s *mapScanScratch[K, V]) scan(
	mapInstance *CiliumEBPF.Map,
	capacity uint32,
	fallbackBudget uint32,
	visit func(K, V),
) (mapScanResult, error) {
	if mapInstance == nil {
		return mapScanResult{}, errBackendClosed
	}
	if capacity == 0 || fallbackBudget == 0 {
		return mapScanResult{}, unix.EINVAL
	}
	if s.lookupSupport.mode.Load() != mapBatchUnsupported {
		count, err := s.scanBatch(mapInstance, capacity, visit)
		if err == nil {
			return mapScanResult{Scanned: count, Entries: count, Complete: true}, nil
		}
		if !mapBatchUnsupportedError(err) {
			return mapScanResult{Scanned: count}, err
		}
		s.lookupSupport.mode.Store(mapBatchUnsupported)
		s.resetFallbackScan()
	}
	return s.scanFallback(mapInstance.FD(), capacity, fallbackBudget, visit)
}

func (s *mapScanScratch[K, V]) scanBatch(
	mapInstance *CiliumEBPF.Map,
	capacity uint32,
	visit func(K, V),
) (uint32, error) {
	if cap(s.keys) < mapBatchMaxEntries {
		s.keys = make([]K, mapBatchMaxEntries)
		s.values = make([]V, mapBatchMaxEntries)
	} else {
		s.keys = s.keys[:mapBatchMaxEntries]
		s.values = s.values[:mapBatchMaxEntries]
	}
	var cursor CiliumEBPF.MapBatchCursor
	var scanned uint32
	for scanned < capacity {
		batchSize := min(uint32(mapBatchMaxEntries), capacity-scanned)
		countValue, err := mapInstance.BatchLookup(
			&cursor,
			s.keys[:batchSize],
			s.values[:batchSize],
			nil,
		)
		count := uint32(countValue)
		for index := range count {
			visit(s.keys[index], s.values[index])
		}
		scanned += count
		if errors.Is(err, CiliumEBPF.ErrKeyNotExist) {
			s.lookupSupport.mode.CompareAndSwap(mapBatchUnknown, mapBatchSupported)
			return scanned, nil
		}
		if err != nil {
			return scanned, err
		}
		if count == 0 {
			return scanned, unix.EIO
		}
		s.lookupSupport.mode.CompareAndSwap(mapBatchUnknown, mapBatchSupported)
	}
	return scanned, nil
}

func (s *mapScanScratch[K, V]) scanFallback(
	mapFD int,
	capacity uint32,
	budget uint32,
	visit func(K, V),
) (mapScanResult, error) {
	if !s.fallbackActive {
		s.fallbackActive = true
		s.cursorValid = false
		var zero K
		s.cursor = zero
	}
	if s.seen == nil {
		s.seen = make(map[K]struct{})
	} else if len(s.seen) > 0 && !s.cursorValid {
		clear(s.seen)
	}
	var scanned uint32
	var attempts uint32
	for uint32(len(s.seen)) < capacity && scanned < budget && attempts < budget*2 {
		attempts++
		var currentPointer unsafe.Pointer
		if s.cursorValid {
			currentPointer = unsafe.Pointer(&s.cursor)
		}
		var next K
		err := mapOperation(bpfMapGetNextKey, mapFD, currentPointer, unsafe.Pointer(&next), 0)
		if errors.Is(err, unix.ENOENT) {
			return s.completeFallbackScan(scanned), nil
		}
		if err != nil {
			return mapScanResult{Scanned: scanned}, err
		}
		s.cursor = next
		s.cursorValid = true
		if _, loaded := s.seen[next]; loaded {
			continue
		}
		s.seen[next] = struct{}{}
		scanned++
		var value V
		if err = lookupMap(mapFD, unsafe.Pointer(&next), unsafe.Pointer(&value)); err != nil {
			if errors.Is(err, unix.ENOENT) {
				continue
			}
			return mapScanResult{Scanned: scanned}, err
		}
		visit(next, value)
	}
	if uint32(len(s.seen)) >= capacity {
		return s.completeFallbackScan(scanned), nil
	}
	return mapScanResult{Scanned: scanned}, nil
}

func (s *mapScanScratch[K, V]) completeFallbackScan(scanned uint32) mapScanResult {
	entries := uint32(len(s.seen))
	s.resetFallbackScan()
	return mapScanResult{Scanned: scanned, Entries: entries, Complete: true}
}

func (s *mapScanScratch[K, V]) resetFallbackScan() {
	s.fallbackActive = false
	s.cursorValid = false
	if s.seen != nil {
		clear(s.seen)
	}
}

func updateMapBatch[K any, V any](
	mapInstance *CiliumEBPF.Map,
	keys []K,
	values []V,
	flags uint64,
	support *mapBatchSupport,
) (uint32, error) {
	if mapInstance == nil {
		return 0, errBackendClosed
	}
	if len(keys) != len(values) {
		return 0, unix.EINVAL
	}
	var total uint32
	for total < uint32(len(keys)) {
		batchCount := min(uint32(len(keys))-total, mapBatchMaxEntries)
		end := total + batchCount
		processed, err := updateMapBatchChunk(
			mapInstance,
			keys[total:end],
			values[total:end],
			flags,
			support,
		)
		total += processed
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func updateMapBatchChunk[K any, V any](
	mapInstance *CiliumEBPF.Map,
	keys []K,
	values []V,
	flags uint64,
	support *mapBatchSupport,
) (uint32, error) {
	if support.mode.Load() != mapBatchUnsupported {
		processedValue, err := mapInstance.BatchUpdate(
			keys,
			values,
			&CiliumEBPF.BatchOptions{ElemFlags: flags},
		)
		processed := uint32(processedValue)
		if err == nil {
			if processed != uint32(len(keys)) {
				return processed, unix.EIO
			}
			support.mode.CompareAndSwap(mapBatchUnknown, mapBatchSupported)
			return processed, nil
		}
		if !mapBatchUnsupportedError(err) {
			return processed, err
		}
		support.mode.Store(mapBatchUnsupported)
	}
	mapFD := mapInstance.FD()
	for index := range keys {
		if err := updateMapWithFlags(
			mapFD,
			unsafe.Pointer(&keys[index]),
			unsafe.Pointer(&values[index]),
			flags,
		); err != nil {
			return uint32(index), err
		}
	}
	return uint32(len(keys)), nil
}

func deleteMapBatch[K any](
	mapInstance *CiliumEBPF.Map,
	keys []K,
	support *mapBatchSupport,
) (uint32, error) {
	if mapInstance == nil {
		return 0, errBackendClosed
	}
	var total uint32
	for total < uint32(len(keys)) {
		batchCount := min(uint32(len(keys))-total, mapBatchMaxEntries)
		end := total + batchCount
		processed, err := deleteMapBatchChunk(mapInstance, keys[total:end], support)
		total += processed
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func deleteMapBatchIfExists[K any](
	mapInstance *CiliumEBPF.Map,
	keys []K,
	support *mapBatchSupport,
) (uint32, error) {
	processed, err := deleteMapBatch(mapInstance, keys, support)
	if err == nil {
		return processed, nil
	}
	if !errors.Is(err, unix.ENOENT) && !errors.Is(err, CiliumEBPF.ErrKeyNotExist) {
		return processed, err
	}
	if mapInstance == nil {
		return processed, errBackendClosed
	}
	mapFD := mapInstance.FD()
	for index := int(processed); index < len(keys); index++ {
		deleteErr := deleteMap(mapFD, unsafe.Pointer(&keys[index]))
		if errors.Is(deleteErr, unix.ENOENT) || errors.Is(deleteErr, CiliumEBPF.ErrKeyNotExist) {
			continue
		}
		if deleteErr != nil {
			return processed, deleteErr
		}
		processed++
	}
	return processed, nil
}

func deleteMapBatchChunk[K any](
	mapInstance *CiliumEBPF.Map,
	keys []K,
	support *mapBatchSupport,
) (uint32, error) {
	if support.mode.Load() != mapBatchUnsupported {
		processedValue, err := mapInstance.BatchDelete(keys, nil)
		processed := uint32(processedValue)
		if err == nil {
			if processed != uint32(len(keys)) {
				return processed, unix.EIO
			}
			support.mode.CompareAndSwap(mapBatchUnknown, mapBatchSupported)
			return processed, nil
		}
		if !mapBatchUnsupportedError(err) {
			return processed, err
		}
		support.mode.Store(mapBatchUnsupported)
	}
	mapFD := mapInstance.FD()
	for index := range keys {
		if err := deleteMap(mapFD, unsafe.Pointer(&keys[index])); err != nil {
			return uint32(index), err
		}
	}
	return uint32(len(keys)), nil
}

func mapBatchUnsupportedError(err error) bool {
	return errors.Is(err, CiliumEBPF.ErrNotSupported) ||
		errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EINVAL) ||
		errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, linuxErrnoNotSupported)
}

func mapOperation(command uintptr, mapFD int, key unsafe.Pointer, value unsafe.Pointer, flags uint64) error {
	if mapFD < 0 {
		return errBackendClosed
	}
	attribute := mapElementAttr{
		MapFD: uint32(mapFD),
		Key:   uint64(uintptr(key)),
		Value: uint64(uintptr(value)),
		Flags: flags,
	}
	_, _, errno := unix.Syscall(unix.SYS_BPF, command, uintptr(unsafe.Pointer(&attribute)), unsafe.Sizeof(attribute))
	runtime.KeepAlive(key)
	runtime.KeepAlive(value)
	if errno != 0 {
		return errno
	}
	return nil
}

var errBackendClosed = syscall.EBADF

func validateMapCapacity(name string, capacity uint32) error {
	if capacity == 0 || capacity > MaxConfigurableMapCapacity {
		return E.New("invalid ", name, " map capacity: ", capacity)
	}
	return nil
}

type backendHealth struct {
	rebuildRequired error
}

func (h *backendHealth) requireUsable(runtimeAvailable bool) error {
	if !runtimeAvailable {
		return errBackendClosed
	}
	return h.rebuildRequired
}

func (h *backendHealth) invalidate(scope string, operation string) error {
	h.rebuildRequired = E.New(scope, " backend requires rebuild after failed ", operation, " rollback")
	return h.rebuildRequired
}

type policyRollbackError struct {
	updateErr   error
	rollbackErr error
}

func (e *policyRollbackError) Error() string {
	return errors.Join(e.updateErr, e.rollbackErr).Error()
}

func (e *policyRollbackError) Unwrap() []error {
	return []error{e.updateErr, e.rollbackErr}
}

func policyUpdateError(updateErr error, rollbackErr error) error {
	if rollbackErr == nil {
		return updateErr
	}
	return &policyRollbackError{updateErr: updateErr, rollbackErr: rollbackErr}
}

func policyRollbackFailed(err error) bool {
	var rollbackErr *policyRollbackError
	return errors.As(err, &rollbackErr)
}

type mapScanScratch[K comparable, V any] struct {
	lookupSupport  mapBatchSupport
	keys           []K
	values         []V
	seen           map[K]struct{}
	cursor         K
	cursorValid    bool
	fallbackActive bool
}

type mapScanResult struct {
	Scanned  uint32
	Entries  uint32
	Complete bool
}
