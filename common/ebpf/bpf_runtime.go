//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"syscall"

	E "github.com/sagernet/sing/common/exceptions"

	CiliumEBPF "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"
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

func eBPFOperationError(operation string, err error) error {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		switch errno {
		case unix.EBUSY:
			return E.Cause(errno, "another eBPF inbound is already active on this attach point: ", operation)
		case unix.ENOSYS, unix.EINVAL, unix.EOPNOTSUPP, linuxErrnoNotSupported:
			return E.Cause(errno, "eBPF inbound is not supported by this kernel: ", operation)
		case unix.EPERM, unix.EACCES:
			return E.Cause(errno, "eBPF inbound is not permitted on this device: ", operation)
		}
	}
	return E.Cause(err, operation)
}

func eBPFBackendOperationError(operation string, stage string, err error) error {
	if stage != "" {
		operation += ": " + stage
	}
	return eBPFOperationError(operation, err)
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
	if err := features.HaveMapType(CiliumEBPF.Array); err != nil {
		return eBPFOperationError("probe "+scope+" BPF_MAP_TYPE_ARRAY", err)
	}
	return nil
}
