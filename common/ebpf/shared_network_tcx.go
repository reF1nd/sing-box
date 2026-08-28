//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"sync"

	E "github.com/sagernet/sing/common/exceptions"

	CiliumEBPF "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

type sharedNetworkTCXLink struct {
	link      link.Link
	linkID    link.ID
	programID CiliumEBPF.ProgramID
	attach    CiliumEBPF.AttachType
}

type SharedNetworkTCXAttachment struct {
	access         sync.Mutex
	interfaceIndex int
	ingress        sharedNetworkTCXLink
	egress         sharedNetworkTCXLink
}

func (b *SharedNetworkBackend) TryAttachTCX(interfaceIndex int) (*SharedNetworkTCXAttachment, bool, error) {
	if b == nil {
		return nil, false, errBackendClosed
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if err := b.requireUsableLocked(); err != nil {
		return nil, false, err
	}
	attachment, err := attachSharedNetworkTCX(
		interfaceIndex,
		b.runtime.programs[sharedNetworkProgramIngress],
		b.runtime.programs[sharedNetworkProgramEgress],
	)
	if err != nil {
		if isTCXUnavailable(err) {
			return nil, false, nil
		}
		return nil, false, E.Cause(err, "attach shared-network TCX")
	}
	return attachment, true, nil
}

func attachSharedNetworkTCX(
	interfaceIndex int,
	ingressProgram *CiliumEBPF.Program,
	egressProgram *CiliumEBPF.Program,
) (*SharedNetworkTCXAttachment, error) {
	ingress, err := attachSharedNetworkTCXLink(interfaceIndex, ingressProgram, CiliumEBPF.AttachTCXIngress)
	if err != nil {
		return nil, err
	}
	egress, err := attachSharedNetworkTCXLink(interfaceIndex, egressProgram, CiliumEBPF.AttachTCXEgress)
	if err != nil {
		return nil, E.Errors(err, ingress.link.Close())
	}
	return &SharedNetworkTCXAttachment{
		interfaceIndex: interfaceIndex,
		ingress:        ingress,
		egress:         egress,
	}, nil
}

func attachSharedNetworkTCXLink(
	interfaceIndex int,
	program *CiliumEBPF.Program,
	attachType CiliumEBPF.AttachType,
) (sharedNetworkTCXLink, error) {
	linkInstance, err := link.AttachTCX(link.TCXOptions{
		Interface: interfaceIndex,
		Program:   program,
		Attach:    attachType,
	})
	if err != nil {
		return sharedNetworkTCXLink{}, err
	}
	info, err := linkInstance.Info()
	if err != nil {
		return sharedNetworkTCXLink{}, E.Errors(err, linkInstance.Close())
	}
	return sharedNetworkTCXLink{
		link:      linkInstance,
		linkID:    info.ID,
		programID: info.Program,
		attach:    attachType,
	}, nil
}

func (b *SharedNetworkBackend) RepairTCX(
	attachment *SharedNetworkTCXAttachment,
	interfaceIndex int,
) (bool, error) {
	if b == nil || attachment == nil {
		return false, errBackendClosed
	}
	attachment.access.Lock()
	defer attachment.access.Unlock()
	healthy, err := attachment.healthyLocked(interfaceIndex)
	if err != nil && !isTCXAttachmentStale(err) {
		return false, err
	}
	if healthy {
		return false, nil
	}

	b.access.RLock()
	defer b.access.RUnlock()
	if err = b.requireUsableLocked(); err != nil {
		return false, err
	}
	replacement, err := attachSharedNetworkTCX(
		interfaceIndex,
		b.runtime.programs[sharedNetworkProgramIngress],
		b.runtime.programs[sharedNetworkProgramEgress],
	)
	if err != nil {
		return false, E.Cause(err, "repair shared-network TCX")
	}
	closeErr := attachment.closeLocked()
	attachment.interfaceIndex = replacement.interfaceIndex
	attachment.ingress = replacement.ingress
	attachment.egress = replacement.egress
	return true, closeErr
}

func (a *SharedNetworkTCXAttachment) healthyLocked(interfaceIndex int) (bool, error) {
	if a.interfaceIndex != interfaceIndex || a.ingress.link == nil || a.egress.link == nil {
		return false, nil
	}
	for _, state := range []sharedNetworkTCXLink{a.ingress, a.egress} {
		result, err := link.QueryPrograms(link.QueryOptions{
			Target: interfaceIndex,
			Attach: state.attach,
		})
		if err != nil {
			return false, err
		}
		found := false
		for _, program := range result.Programs {
			if program.ID != state.programID {
				continue
			}
			linkID, haveLinkID := program.LinkID()
			if !haveLinkID || linkID == state.linkID {
				found = true
				break
			}
		}
		if !found {
			return false, nil
		}
	}
	return true, nil
}

func (a *SharedNetworkTCXAttachment) Close() error {
	if a == nil {
		return nil
	}
	a.access.Lock()
	defer a.access.Unlock()
	return a.closeLocked()
}

func (a *SharedNetworkTCXAttachment) closeLocked() error {
	var closeErr error
	if a.ingress.link != nil {
		closeErr = E.Errors(closeErr, a.ingress.link.Close())
		a.ingress = sharedNetworkTCXLink{}
	}
	if a.egress.link != nil {
		closeErr = E.Errors(closeErr, a.egress.link.Close())
		a.egress = sharedNetworkTCXLink{}
	}
	return closeErr
}

func isTCXUnavailable(err error) bool {
	return errors.Is(err, link.ErrNotSupported) ||
		errors.Is(err, unix.ENOSYS) ||
		errors.Is(err, unix.EINVAL) ||
		errors.Is(err, unix.EOPNOTSUPP) ||
		errors.Is(err, unix.ENOTSUP) ||
		errors.Is(err, linuxErrnoNotSupported) ||
		errors.Is(err, unix.EPERM) ||
		errors.Is(err, unix.EACCES)
}

func isTCXAttachmentStale(err error) bool {
	return errors.Is(err, unix.ENOENT) ||
		errors.Is(err, unix.ENODEV) ||
		errors.Is(err, unix.ENOLINK) ||
		errors.Is(err, unix.ESTALE)
}
