//go:build linux

package libbox

import (
	"net"
	"os"
	"testing"
	"time"
)

func TestAutoRedirectListenerTransfer(t *testing.T) {
	for _, inet6 := range []bool{false, true} {
		name := "IPv4"
		if inet6 {
			name = "dual-stack"
		}
		t.Run(name, func(t *testing.T) {
			fd, err := NewAutoRedirectListener(inet6, "")
			if err != nil {
				t.Fatal(err)
			}
			file := os.NewFile(uintptr(fd), "redirect-listener")
			listener, err := net.FileListener(file)
			_ = file.Close()
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			tcpListener := listener.(*net.TCPListener)
			_ = tcpListener.SetDeadline(time.Now().Add(5 * time.Second))
			networks := []string{"tcp4"}
			if inet6 {
				networks = append(networks, "tcp6")
			}
			for _, network := range networks {
				host := "127.0.0.1"
				if network == "tcp6" {
					host = "::1"
				}
				_, port, _ := net.SplitHostPort(listener.Addr().String())
				conn, err := net.DialTimeout(network, net.JoinHostPort(host, port), 5*time.Second)
				if err != nil {
					t.Fatal(err)
				}
				accepted, err := listener.Accept()
				if err != nil {
					conn.Close()
					t.Fatal(err)
				}
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				_ = accepted.SetDeadline(time.Now().Add(5 * time.Second))
				if _, err = conn.Write([]byte{42}); err != nil {
					t.Error(err)
				}
				var b [1]byte
				if _, err = accepted.Read(b[:]); err != nil || b[0] != 42 {
					t.Errorf("handoff read: %v, %v", b, err)
				}
				if _, err = accepted.Write([]byte{43}); err != nil {
					t.Error(err)
				}
				if _, err = conn.Read(b[:]); err != nil || b[0] != 43 {
					t.Errorf("handoff reply: %v, %v", b, err)
				}
				_ = conn.Close()
				_ = accepted.Close()
			}
		})
	}
}
