//go:build linux

package tun

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"golang.org/x/sys/unix"
)

func TestAutoRedirectListenerFromFD(t *testing.T) {
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Fatal(err)
	}
	file, err := listener.File()
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	// Use a raw owned descriptor, as received from Binder.
	fd, err := unix.Dup(int(file.Fd()))
	_ = file.Close()
	if err != nil {
		t.Fatal(err)
	}
	adopted, err := autoRedirectListenerFromFD(fd)
	if err != nil {
		t.Fatal(err)
	}
	defer adopted.Close()
	if adopted.Addr().String() != address {
		t.Fatal("listener address changed")
	}
	if _, err = unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
		t.Fatalf("input fd was not closed: %v", err)
	}
	conn, err := net.Dial("tcp4", address)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	accepted, err := adopted.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	_ = accepted.Close()
}

func TestAutoRedirectListenerFromFDRejectsNonSocket(t *testing.T) {
	file, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	fd, err := unix.Dup(int(file.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = autoRedirectListenerFromFD(fd); err == nil {
		t.Fatal("accepted non-socket")
	}
	if _, err = unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
		t.Fatalf("input fd was not closed: %v", err)
	}
	if _, err = autoRedirectListenerFromFD(-1); err == nil {
		t.Fatal("accepted invalid fd")
	}
}

type redirectListenerFailurePlatform struct {
	adapter.PlatformInterface
	fd          int
	startErr    error
	listenerErr error
	duplicate   int
}

func (p *redirectListenerFailurePlatform) CreateAutoRedirectListener(bool) (int, error) {
	return p.fd, p.listenerErr
}
func (p *redirectListenerFailurePlatform) CreateAutoRedirect(options adapter.AutoRedirectOptions) (adapter.AutoRedirectSession, error) {
	fd, err := options.RedirectListenerFileDescriptor()
	if err != nil {
		return nil, err
	}
	p.duplicate = fd
	_ = unix.Close(fd)
	return nil, p.startErr
}

func TestPlatformAutoRedirectStartFailureClosesListener(t *testing.T) {
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Fatal(err)
	}
	file, err := listener.File()
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().(*net.TCPAddr)
	_ = listener.Close()
	fd, err := unix.Dup(int(file.Fd()))
	_ = file.Close()
	if err != nil {
		t.Fatal(err)
	}
	expected := errors.New("rules failed")
	platform := &redirectListenerFailurePlatform{fd: fd, startErr: expected, duplicate: -1}
	redirect := &platformAutoRedirect{inbound: &Inbound{ctx: context.Background(), logger: log.NewNOPFactory().Logger(), platformInterface: platform}}
	if err = redirect.Start(); !errors.Is(err, expected) {
		t.Fatalf("start error: %v", err)
	}
	// Closing only the temporary Binder FD would leave the listener port busy.
	rebound, err := net.ListenTCP("tcp4", addr)
	if err != nil {
		t.Fatalf("listener leaked after failed startup: %v", err)
	}
	_ = rebound.Close()
	if platform.duplicate < 0 {
		t.Fatal("root could not get listener for transparent setup")
	}
	if err = redirect.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestPlatformAutoRedirectListenerFailure(t *testing.T) {
	expected := errors.New("root unavailable")
	platform := &redirectListenerFailurePlatform{fd: -1, listenerErr: expected}
	redirect := &platformAutoRedirect{inbound: &Inbound{ctx: context.Background(), logger: log.NewNOPFactory().Logger(), platformInterface: platform}}
	redirect.inbound.tunOptions.Inet6Address = []netip.Prefix{netip.MustParsePrefix("fd00::1/126")}
	if err := redirect.Start(); !errors.Is(err, expected) {
		t.Fatalf("start error: %v", err)
	}
	if err := redirect.Close(); err != nil {
		t.Fatal(err)
	}
}
