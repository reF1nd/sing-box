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

func TestSocketProtectTGIDFastPath(t *testing.T) {
	backend := &CgroupBackend{
		runtime: &cgroupRuntime{self_bypass_tgid: true},
	}
	backend.selfBypassTGID.Store(true)
	if err := backend.SocketProtectFunc()("tcp4", "example.com:443", nil); err != nil {
		t.Fatal(err)
	}
}
