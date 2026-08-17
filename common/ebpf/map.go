//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"runtime"
	"sync/atomic"
	"syscall"
	"unsafe"

	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/sys/unix"
)

const (
	bpfMapLookupElem          = 1
	bpfMapUpdateElem          = 2
	bpfMapDeleteElem          = 3
	bpfMapGetNextKey          = 4
	bpfMapLookupAndDeleteElem = 21
	bpfMapLookupBatch         = 24
	bpfMapUpdateBatch         = 26
	bpfMapDeleteBatch         = 27
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

type mapBatchAttr struct {
	InBatch   uint64
	OutBatch  uint64
	Keys      uint64
	Values    uint64
	Count     uint32
	MapFD     uint32
	ElemFlags uint64
	Flags     uint64
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

func countMapEntries(mapFD int, keySize uintptr, capacity uint32) (uint32, error) {
	if keySize == 0 || capacity == 0 {
		return 0, unix.EINVAL
	}
	current := make([]byte, keySize)
	next := make([]byte, keySize)
	seen := make(map[string]struct{})
	var currentPointer unsafe.Pointer
	for uint32(len(seen)) <= capacity {
		err := mapOperation(
			bpfMapGetNextKey,
			mapFD,
			currentPointer,
			unsafe.Pointer(&next[0]),
			0,
		)
		if errors.Is(err, unix.ENOENT) {
			return uint32(len(seen)), nil
		}
		if err != nil {
			return 0, err
		}
		encoded := string(next)
		if _, loaded := seen[encoded]; loaded {
			return uint32(len(seen)), nil
		}
		seen[encoded] = struct{}{}
		copy(current, next)
		currentPointer = unsafe.Pointer(&current[0])
	}
	return uint32(len(seen)), nil
}

func (s *mapScanScratch[K, V]) scan(
	mapFD int,
	capacity uint32,
	fallbackBudget uint32,
	visit func(K, V),
) (mapScanResult, error) {
	if capacity == 0 || fallbackBudget == 0 {
		return mapScanResult{}, unix.EINVAL
	}
	if s.lookupSupport.mode.Load() != mapBatchUnsupported {
		count, err := s.scanBatch(mapFD, capacity, visit)
		if err == nil {
			return mapScanResult{Scanned: count, Entries: count, Complete: true}, nil
		}
		if !mapBatchUnsupportedError(err) {
			return mapScanResult{Scanned: count}, err
		}
		s.lookupSupport.mode.Store(mapBatchUnsupported)
		s.resetFallbackScan()
	}
	return s.scanFallback(mapFD, capacity, fallbackBudget, visit)
}

func (s *mapScanScratch[K, V]) scanBatch(
	mapFD int,
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
	var cursor K
	var cursorPointer unsafe.Pointer
	var scanned uint32
	for scanned < capacity {
		batchSize := min(uint32(mapBatchMaxEntries), capacity-scanned)
		count, err := lookupMapBatch(
			mapFD,
			cursorPointer,
			unsafe.Pointer(&cursor),
			unsafe.Pointer(&s.keys[0]),
			unsafe.Pointer(&s.values[0]),
			batchSize,
		)
		for index := range count {
			visit(s.keys[index], s.values[index])
		}
		scanned += count
		if errors.Is(err, unix.ENOENT) {
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
		cursorPointer = unsafe.Pointer(&cursor)
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

func lookupMapBatch(
	mapFD int,
	inBatch unsafe.Pointer,
	outBatch unsafe.Pointer,
	keys unsafe.Pointer,
	values unsafe.Pointer,
	count uint32,
) (uint32, error) {
	if mapFD < 0 {
		return 0, errBackendClosed
	}
	attribute := mapBatchAttr{
		InBatch:  uint64(uintptr(inBatch)),
		OutBatch: uint64(uintptr(outBatch)),
		Keys:     uint64(uintptr(keys)),
		Values:   uint64(uintptr(values)),
		Count:    count,
		MapFD:    uint32(mapFD),
	}
	_, _, errno := unix.Syscall(
		unix.SYS_BPF,
		bpfMapLookupBatch,
		uintptr(unsafe.Pointer(&attribute)),
		unsafe.Sizeof(attribute),
	)
	runtime.KeepAlive(inBatch)
	runtime.KeepAlive(outBatch)
	runtime.KeepAlive(keys)
	runtime.KeepAlive(values)
	if errno != 0 {
		return attribute.Count, errno
	}
	return attribute.Count, nil
}

func updateMapBatch(
	mapFD int,
	keys unsafe.Pointer,
	values unsafe.Pointer,
	count uint32,
	keySize uintptr,
	valueSize uintptr,
	flags uint64,
	support *mapBatchSupport,
) (uint32, error) {
	if count == 0 {
		return 0, nil
	}
	var total uint32
	for total < count {
		batchCount := min(count-total, mapBatchMaxEntries)
		processed, err := updateMapBatchChunk(
			mapFD,
			unsafe.Add(keys, uintptr(total)*keySize),
			unsafe.Add(values, uintptr(total)*valueSize),
			batchCount,
			keySize,
			valueSize,
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

func updateMapBatchChunk(
	mapFD int,
	keys unsafe.Pointer,
	values unsafe.Pointer,
	count uint32,
	keySize uintptr,
	valueSize uintptr,
	flags uint64,
	support *mapBatchSupport,
) (uint32, error) {
	if support.mode.Load() != mapBatchUnsupported {
		processed, err := mapBatchOperation(bpfMapUpdateBatch, mapFD, keys, values, count, flags)
		if err == nil {
			if processed != count {
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
	for index := uint32(0); index < count; index++ {
		if err := updateMapWithFlags(
			mapFD,
			unsafe.Add(keys, uintptr(index)*keySize),
			unsafe.Add(values, uintptr(index)*valueSize),
			flags,
		); err != nil {
			return index, err
		}
	}
	return count, nil
}

func deleteMapBatch(
	mapFD int,
	keys unsafe.Pointer,
	count uint32,
	keySize uintptr,
	support *mapBatchSupport,
) (uint32, error) {
	if count == 0 {
		return 0, nil
	}
	var total uint32
	for total < count {
		batchCount := min(count-total, mapBatchMaxEntries)
		processed, err := deleteMapBatchChunk(
			mapFD,
			unsafe.Add(keys, uintptr(total)*keySize),
			batchCount,
			keySize,
			support,
		)
		total += processed
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func deleteMapBatchChunk(
	mapFD int,
	keys unsafe.Pointer,
	count uint32,
	keySize uintptr,
	support *mapBatchSupport,
) (uint32, error) {
	if support.mode.Load() != mapBatchUnsupported {
		processed, err := mapBatchOperation(bpfMapDeleteBatch, mapFD, keys, nil, count, 0)
		if err == nil {
			if processed != count {
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
	for index := uint32(0); index < count; index++ {
		if err := deleteMap(mapFD, unsafe.Add(keys, uintptr(index)*keySize)); err != nil {
			return index, err
		}
	}
	return count, nil
}

func mapBatchOperation(
	command uintptr,
	mapFD int,
	keys unsafe.Pointer,
	values unsafe.Pointer,
	count uint32,
	elemFlags uint64,
) (uint32, error) {
	if mapFD < 0 {
		return 0, errBackendClosed
	}
	attribute := mapBatchAttr{
		Keys:      uint64(uintptr(keys)),
		Values:    uint64(uintptr(values)),
		Count:     count,
		MapFD:     uint32(mapFD),
		ElemFlags: elemFlags,
	}
	_, _, errno := unix.Syscall(
		unix.SYS_BPF,
		command,
		uintptr(unsafe.Pointer(&attribute)),
		unsafe.Sizeof(attribute),
	)
	runtime.KeepAlive(keys)
	runtime.KeepAlive(values)
	if errno != 0 {
		return attribute.Count, errno
	}
	return attribute.Count, nil
}

func mapBatchUnsupportedError(err error) bool {
	return errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EINVAL) ||
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

func readSocketCookie(fd uintptr) (uint64, error) {
	var cookie uint64
	length := uint32(unsafe.Sizeof(cookie))
	_, _, errno := unix.Syscall6(
		unix.SYS_GETSOCKOPT,
		fd,
		unix.SOL_SOCKET,
		unix.SO_COOKIE,
		uintptr(unsafe.Pointer(&cookie)),
		uintptr(unsafe.Pointer(&length)),
		0,
	)
	if errno != 0 {
		return 0, errno
	}
	return cookie, nil
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
