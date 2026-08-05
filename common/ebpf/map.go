//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"

	E "github.com/sagernet/sing/common/exceptions"
)

const (
	bpfMapCreate              = 0
	bpfMapLookupElem          = 1
	bpfMapUpdateElem          = 2
	bpfMapDeleteElem          = 3
	bpfMapLookupAndDeleteElem = 21
	bpfMapTypeArray           = 2
	bpfNoExist                = 1
)

type mapElementAttr struct {
	MapFD uint32
	_     uint32
	Key   uint64
	Value uint64
	Flags uint64
}

type mapCreateAttr struct {
	MapType    uint32
	KeySize    uint32
	ValueSize  uint32
	MaxEntries uint32
	MapFlags   uint32
}

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
