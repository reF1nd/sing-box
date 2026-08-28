//go:build with_ebpf && ebpf_integration && (linux || android)

package ebpf

import (
	"errors"
	"net/netip"
	"unsafe"

	"golang.org/x/sys/unix"
)

func countMapEntriesForTest(mapFD int, keySize uintptr, capacity uint32) (uint32, error) {
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

func usesSocketReleaseForTest(backend *CgroupBackend) bool {
	if backend == nil {
		return false
	}
	backend.access.RLock()
	defer backend.access.RUnlock()
	return backend.runtime != nil && backend.runtime.socket_release_supported &&
		backend.runtime.programs[cgroupProgramSocketRelease] != nil
}

func updateCgroupBypassCIDRForTest(backend *CgroupBackend, prefixes []netip.Prefix) (bool, error) {
	policy, err := CompileBypassCIDRPolicy(prefixes)
	if err != nil {
		return false, err
	}
	return backend.UpdateCompiledBypassCIDR(policy)
}

func updateSharedBypassCIDRForTest(backend *SharedNetworkBackend, prefixes []netip.Prefix) (bool, error) {
	policy, err := CompileBypassCIDRPolicy(prefixes)
	if err != nil {
		return false, err
	}
	return backend.UpdateCompiledBypassCIDR(policy)
}
