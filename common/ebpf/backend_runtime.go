//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"syscall"

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
