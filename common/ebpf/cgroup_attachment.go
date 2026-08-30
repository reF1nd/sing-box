//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"strings"

	E "github.com/sagernet/sing/common/exceptions"

	CiliumEBPF "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

func detachOwnedCgroupPrograms(cgroupFD int) error {
	for _, definition := range cgroupProgramDefinitions {
		first, err := queryCgroupProgramIDs(cgroupFD, definition.attachType)
		if err != nil {
			if definition.attachType == CiliumEBPF.AttachCgroupInetSockRelease && socketReleaseUnavailable(err) {
				continue
			}
			return err
		}
		second, err := queryCgroupProgramIDs(cgroupFD, definition.attachType)
		if err != nil {
			return err
		}
		if !sameProgramIDs(first, second) {
			return unix.ESTALE
		}
		for _, programID := range first {
			program, openErr := CiliumEBPF.NewProgramFromID(programID)
			if openErr != nil {
				return openErr
			}
			info, infoErr := program.Info()
			if infoErr != nil {
				_ = program.Close()
				return infoErr
			}
			if strings.HasPrefix(info.Name, "sb_ebpf_") {
				if detachErr := rawDetachProgram(cgroupFD, program, definition.attachType); detachErr != nil {
					_ = program.Close()
					return detachErr
				}
			}
			if closeErr := program.Close(); closeErr != nil {
				return closeErr
			}
		}
	}
	return nil
}

func queryCgroupProgramIDs(cgroupFD int, attachType CiliumEBPF.AttachType) ([]CiliumEBPF.ProgramID, error) {
	result, err := link.QueryPrograms(link.QueryOptions{Target: cgroupFD, Attach: attachType})
	if err != nil {
		return nil, err
	}
	ids := make([]CiliumEBPF.ProgramID, len(result.Programs))
	for index := range result.Programs {
		ids[index] = result.Programs[index].ID
	}
	return ids, nil
}

func (b *CgroupBackend) Attach() error {
	if b == nil {
		return errBackendClosed
	}
	b.access.Lock()
	defer b.access.Unlock()
	if err := b.health.requireUsable(b.runtime != nil); err != nil {
		return err
	}
	cgroupFD := int(b.runtime.cgroupFile.Fd())
	attachOrder := make([]int, 0, cgroupProgramCount)
	if b.runtime.programs[cgroupProgramSocketRelease] != nil {
		attachOrder = append(attachOrder, cgroupProgramSocketRelease)
	}
	for slot := range b.runtime.programs {
		if slot != cgroupProgramSocketRelease {
			attachOrder = append(attachOrder, slot)
		}
	}
	for _, slot := range attachOrder {
		program := b.runtime.programs[slot]
		if program == nil {
			continue
		}
		programLink, err := link.AttachRawLink(link.RawLinkOptions{
			Target:  cgroupFD,
			Program: program,
			Attach:  cgroupProgramDefinitions[slot].attachType,
		})
		if err == nil {
			b.runtime.links[slot] = programLink
		} else if cgroupLinkUnavailable(err) {
			err = attachProgramRaw(cgroupFD, program, cgroupProgramDefinitions[slot].attachType)
		}
		if err != nil {
			_ = b.detachProgramsLocked()
			return eBPFBackendOperationError("attach eBPF inbound", cgroupProgramDefinitions[slot].name, err)
		}
		b.runtime.attached[slot] = true
	}
	if b.runtime.enable_udp && b.runtime.socket_release_supported &&
		!b.runtime.attached[cgroupProgramSocketRelease] {
		_ = b.detachProgramsLocked()
		return eBPFOperationError("attach eBPF inbound UDP cleanup", unix.EINVAL)
	}
	return nil
}

func cgroupLinkUnavailable(err error) bool {
	return errors.Is(err, link.ErrNotSupported) ||
		errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOSYS) ||
		errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EOPNOTSUPP) ||
		errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) ||
		errors.Is(err, linuxErrnoNotSupported)
}

func (b *CgroupBackend) detachProgramsLocked() error {
	if b.runtime == nil || b.runtime.cgroupFile == nil {
		return nil
	}
	cgroupFD := int(b.runtime.cgroupFile.Fd())
	var detachErr error
	for slot := cgroupProgramCount - 1; slot >= 0; slot-- {
		if !b.runtime.attached[slot] {
			continue
		}
		programLink := b.runtime.links[slot]
		var err error
		if programLink != nil {
			err = programLink.Close()
			b.runtime.links[slot] = nil
			b.runtime.attached[slot] = false
			if err != nil {
				detachErr = E.Errors(detachErr, err)
			}
			continue
		} else {
			err = rawDetachProgram(cgroupFD, b.runtime.programs[slot], cgroupProgramDefinitions[slot].attachType)
		}
		if err == nil || errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ESRCH) {
			b.runtime.attached[slot] = false
			continue
		}
		detachErr = E.Errors(detachErr, err)
	}
	return detachErr
}
