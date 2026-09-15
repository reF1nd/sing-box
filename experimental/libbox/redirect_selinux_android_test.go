package libbox

import (
	"bytes"
	"errors"
	"net"
	"os"
	"runtime"
	"strings"
	"testing"
)

func TestSocketCreateContext(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root to set socket labels")
	}
	label, err := os.ReadFile("/proc/self/attr/current")
	if err != nil {
		t.Fatal(err)
	}
	context := strings.TrimRight(string(label), "\x00\n")
	if override := os.Getenv("SFA_TEST_SOCKET_CONTEXT"); override != "" {
		context = override
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	before, err := os.ReadFile("/proc/thread-self/attr/sockcreate")
	if err != nil {
		t.Fatal(err)
	}
	expected := errors.New("listen failed")
	var observed []byte
	_, err = withSocketCreateContext(context, func() (net.Listener, error) {
		var readErr error
		observed, readErr = os.ReadFile("/proc/thread-self/attr/sockcreate")
		if readErr != nil {
			return nil, readErr
		}
		return nil, expected
	})
	if !errors.Is(err, expected) {
		t.Fatalf("listen error = %v", err)
	}
	if strings.TrimRight(string(observed), "\x00\n") != context {
		t.Fatalf("socket context = %q", observed)
	}
	after, err := os.ReadFile("/proc/thread-self/attr/sockcreate")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatalf("caller context changed: %q -> %q", before, after)
	}
	if _, err = withSocketCreateContext("invalid SELinux context", func() (net.Listener, error) {
		return nil, errors.New("unexpected listen")
	}); err == nil || !strings.Contains(err.Error(), "set socket SELinux context") {
		t.Fatalf("invalid context error = %v", err)
	}
	// The actual root-side socket factory also succeeds under the caller's label.
	for _, inet6 := range []bool{false, true} {
		fd, err := NewAutoRedirectListener(inet6, context)
		if err != nil {
			t.Fatal(err)
		}
		file := os.NewFile(uintptr(fd), "listener")
		_ = file.Close()
	}
}
