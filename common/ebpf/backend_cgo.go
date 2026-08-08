//go:build with_ebpf && (linux || android) && cgo

package ebpf

import (
	"syscall"
	"unsafe"

	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/sys/unix"
)

func raiseMemlockLimit() error {
	unlimited := unix.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	}
	unlimitedErr := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unlimited)
	if unlimitedErr == nil {
		return nil
	}

	var limit unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &limit); err != nil {
		return E.Errors(unlimitedErr, E.Cause(err, "read memlock limit"))
	}
	if limit.Cur < limit.Max {
		limit.Cur = limit.Max
		if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &limit); err != nil {
			return E.Errors(unlimitedErr, E.Cause(err, "raise soft memlock limit"))
		}
	}
	return unlimitedErr
}

func checkKernelCapabilities(scope string, cgroupPath string) error {
	if cgroupPath != "" {
		var fileSystem unix.Statfs_t
		if err := unix.Statfs(cgroupPath, &fileSystem); err != nil {
			return E.Cause(err, "check ", scope, " eBPF cgroup2 mount")
		}
		if fileSystem.Type != unix.CGROUP2_SUPER_MAGIC {
			return E.New("eBPF inbound is not supported: ", cgroupPath, " is not a cgroup2 mount")
		}
	}

	attribute := mapCreateAttr{
		MapType:    bpfMapTypeArray,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 1,
	}
	fd, _, errno := unix.Syscall(
		unix.SYS_BPF,
		bpfMapCreate,
		uintptr(unsafe.Pointer(&attribute)),
		unsafe.Sizeof(attribute),
	)
	if errno != 0 {
		return eBPFOperationError("probe "+scope+" BPF_MAP_CREATE", errno)
	}
	if err := unix.Close(int(fd)); err != nil {
		return E.Cause(err, "close eBPF capability probe map")
	}
	return nil
}

func eBPFBackendOperationError(operation string, stage string, err error) error {
	if stage != "" {
		operation += ": " + stage
	}
	return eBPFOperationError(operation, err)
}

func eBPFOperationError(operation string, err error) error {
	if errno, isErrno := err.(syscall.Errno); isErrno {
		switch errno {
		case unix.EBUSY:
			return E.Cause(errno, "another eBPF inbound is already active on this cgroup: ", operation)
		case unix.ENOSYS, unix.EINVAL, unix.EOPNOTSUPP:
			return E.Cause(errno, "eBPF inbound is not supported by this kernel: ", operation)
		case unix.EPERM, unix.EACCES:
			return E.Cause(errno, "eBPF inbound is not permitted on this device: ", operation)
		}
	}
	return E.Cause(err, operation)
}
