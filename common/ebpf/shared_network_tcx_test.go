//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

func TestTCXUnavailable(t *testing.T) {
	for _, err := range []error{
		link.ErrNotSupported,
		unix.ENOSYS,
		unix.EINVAL,
		unix.EOPNOTSUPP,
		linuxErrnoNotSupported,
		unix.EPERM,
		errors.Join(errors.New("attach TCX"), unix.EACCES),
	} {
		if !isTCXUnavailable(err) {
			t.Fatalf("expected TCX error to allow fallback: %v", err)
		}
	}
	if isTCXUnavailable(unix.ENOMEM) {
		t.Fatal("unexpectedly allowed TCX fallback after allocation failure")
	}
}

func TestTCXAttachmentStale(t *testing.T) {
	for _, err := range []error{unix.ENOENT, unix.ENODEV, unix.ENOLINK, unix.ESTALE} {
		if !isTCXAttachmentStale(err) {
			t.Fatalf("expected stale TCX attachment error: %v", err)
		}
	}
	if isTCXAttachmentStale(unix.EPERM) {
		t.Fatal("unexpectedly treated TCX permission failure as stale")
	}
}
