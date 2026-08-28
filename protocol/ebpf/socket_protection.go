//go:build with_ebpf && (linux || android)

package ebpf

import (
	"sync"
	"syscall"

	"github.com/sagernet/sing-box/common/ebpf"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/sys/unix"
)

const maxPendingSocketCookies = 32768

type socketProtector struct {
	access  sync.Mutex
	backend *ebpf.CgroupBackend
	pending map[uint64]struct{}
	closed  bool
}

func newSocketProtector() *socketProtector {
	return &socketProtector{pending: make(map[uint64]struct{})}
}

func (p *socketProtector) ControlFunc() control.Func {
	return func(_ string, _ string, rawConn syscall.RawConn) error {
		cookie, err := control.Raw0(rawConn, func(fd uintptr) (uint64, error) {
			return unix.GetsockoptUint64(int(fd), unix.SOL_SOCKET, unix.SO_COOKIE)
		})
		if err != nil {
			return E.Cause(err, "read socket cookie")
		}
		return p.protectCookie(cookie)
	}
}

func (p *socketProtector) protectCookie(cookie uint64) error {
	if cookie == 0 {
		return E.New("invalid socket cookie")
	}
	p.access.Lock()
	defer p.access.Unlock()
	if p.closed {
		return nil
	}
	if p.backend != nil {
		return p.backend.RegisterProtectedSocket(cookie)
	}
	if _, loaded := p.pending[cookie]; loaded {
		return nil
	}
	if len(p.pending) >= maxPendingSocketCookies {
		return E.New("pending eBPF protected socket capacity exceeded")
	}
	p.pending[cookie] = struct{}{}
	return nil
}

func (p *socketProtector) Attach(backend *ebpf.CgroupBackend) error {
	if backend == nil {
		return E.New("cgroup eBPF backend is nil")
	}
	p.access.Lock()
	defer p.access.Unlock()
	if p.closed {
		return E.New("eBPF socket protector is closed")
	}
	if p.backend != nil {
		return E.New("eBPF socket protector is already attached")
	}
	for cookie := range p.pending {
		if err := backend.RegisterProtectedSocket(cookie); err != nil {
			return E.Cause(err, "flush pending protected socket")
		}
	}
	p.backend = backend
	p.pending = nil
	return nil
}

func (p *socketProtector) Close() {
	if p == nil {
		return
	}
	p.access.Lock()
	p.closed = true
	p.backend = nil
	p.pending = nil
	p.access.Unlock()
}
