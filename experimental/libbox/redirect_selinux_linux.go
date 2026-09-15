//go:build linux

package libbox

import (
	"net"
	"os"
	"runtime"

	E "github.com/sagernet/sing/common/exceptions"
)

// withSocketCreateContext changes only the socket label, not the creating UID
// or the process domain. Android checks both the socket's SELinux label when
// transferring its FD and its creator UID when routing cross-user loopback.
func withSocketCreateContext(socketContext string, listen func() (net.Listener, error)) (net.Listener, error) {
	if socketContext == "" {
		return listen()
	}
	type result struct {
		listener net.Listener
		err      error
	}
	done := make(chan result, 1)
	// Use a dedicated goroutine: if restoring the label fails, its locked OS
	// thread must be discarded rather than returned to Go or a Binder caller.
	go func() {
		runtime.LockOSThread()
		const path = "/proc/thread-self/attr/sockcreate"
		previous, err := os.ReadFile(path)
		if err != nil {
			runtime.UnlockOSThread()
			done <- result{err: E.Cause(err, "read socket SELinux context")}
			return
		}
		if len(previous) == 0 {
			previous = []byte{0} // A zero-length os.WriteFile would not reset the label.
		}
		err = os.WriteFile(path, []byte(socketContext), 0)
		if err != nil {
			runtime.UnlockOSThread()
			done <- result{err: E.Cause(err, "set socket SELinux context")}
			return
		}
		listener, listenErr := listen()
		restoreErr := os.WriteFile(path, previous, 0)
		if restoreErr != nil {
			if listener != nil {
				_ = listener.Close()
			}
			done <- result{err: E.Errors(listenErr, E.Cause(restoreErr, "restore socket SELinux context"))}
			return
		}
		runtime.UnlockOSThread()
		done <- result{listener: listener, err: listenErr}
	}()
	resultValue := <-done
	return resultValue.listener, resultValue.err
}
