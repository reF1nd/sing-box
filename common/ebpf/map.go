//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"runtime"
	"sync/atomic"
	"syscall"
	"unsafe"

	CiliumEBPF "github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

const (
	bpfMapLookupElem = 1
	bpfMapUpdateElem = 2
	bpfMapDeleteElem = 3
	bpfMapGetNextKey = 4
	bpfNoExist       = 1

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

func updateMap(mapFD int, key unsafe.Pointer, value unsafe.Pointer) error {
	return updateMapWithFlags(mapFD, key, value, 0)
}

func updateMapWithFlags(mapFD int, key unsafe.Pointer, value unsafe.Pointer, flags uint64) error {
	return mapOperation(bpfMapUpdateElem, mapFD, key, value, flags)
}

func deleteMap(mapFD int, key unsafe.Pointer) error {
	return mapOperation(bpfMapDeleteElem, mapFD, key, nil, 0)
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
