//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"testing"

	"golang.org/x/sys/unix"
)

func TestMapLookupAndDeleteUnavailable(t *testing.T) {
	testCases := []struct {
		name        string
		err         error
		unavailable bool
	}{
		{"not implemented", unix.ENOSYS, true},
		{"invalid command", unix.EINVAL, true},
		{"operation not supported", unix.EOPNOTSUPP, true},
		{"Android kernel ENOTSUPP", linuxErrnoNotSupported, true},
		{"missing element", unix.ENOENT, false},
		{"wrapped Android kernel ENOTSUPP", errors.Join(errors.New("lookup map"), linuxErrnoNotSupported), true},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			if mapLookupAndDeleteUnavailable(testCase.err) != testCase.unavailable {
				t.Fatal("unexpected lookup-and-delete availability result")
			}
		})
	}
}

func TestRegisterProtectedSocketRejectsZeroCookie(t *testing.T) {
	if err := new(CgroupBackend).RegisterProtectedSocket(0); err == nil {
		t.Fatal("accepted a zero socket cookie")
	}
}
