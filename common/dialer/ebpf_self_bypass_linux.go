//go:build with_ebpf && (linux || android)

package dialer

import (
	"net"
	"runtime"
	"sync"
	"syscall"

	commonEBPF "github.com/CHIZI-0618/sing-ebpf"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
)

// bindEBPFSelfBypassConnLifecycle pairs userspace socket registration with the
// returned connection's Close method. Kernel sock_release cleanup remains the
// fast path when available; this closes the gap on kernels where only the
// userspace registration fallback can be used.
func bindEBPFSelfBypassConnLifecycle(networkManager adapter.NetworkManager, conn net.Conn) net.Conn {
	provider, loaded := networkManager.(interface {
		EBPFSelfBypass() *commonEBPF.SelfBypass
	})
	if !loaded || provider.EBPFSelfBypass() == nil {
		return conn
	}
	tracker := provider.EBPFSelfBypass()
	if tracker.CleanupMode() != "lru_fallback" {
		return conn
	}
	if lazyConn, loaded := conn.(*slowOpenConn); loaded {
		lazyConn.setCloseHandler(func(tcpConn *net.TCPConn) {
			rawConn, err := tcpConn.SyscallConn()
			if err == nil {
				_ = tracker.UnregisterSocket(rawConn)
			}
		})
		return conn
	}
	syscallConn, loaded := conn.(syscall.Conn)
	if !loaded {
		return conn
	}
	rawConn, err := syscallConn.SyscallConn()
	if err != nil {
		return conn
	}
	return &selfBypassConn{Conn: conn, cleanup: EBPFSelfBypassCleanup(networkManager, rawConn), rawConn: rawConn}
}

func bindEBPFSelfBypassPacketConnLifecycle(networkManager adapter.NetworkManager, conn net.PacketConn) net.PacketConn {
	provider, loaded := networkManager.(interface {
		EBPFSelfBypass() *commonEBPF.SelfBypass
	})
	if !loaded || provider.EBPFSelfBypass() == nil {
		return conn
	}
	tracker := provider.EBPFSelfBypass()
	if tracker.CleanupMode() != "lru_fallback" {
		return conn
	}
	syscallConn, loaded := conn.(syscall.Conn)
	if !loaded {
		return conn
	}
	rawConn, err := syscallConn.SyscallConn()
	if err != nil {
		return conn
	}
	return &selfBypassPacketConn{PacketConn: conn, cleanup: EBPFSelfBypassCleanup(networkManager, rawConn), rawConn: rawConn}
}

type selfBypassConn struct {
	net.Conn
	cleanup func()
	rawConn syscall.RawConn
}

func (c *selfBypassConn) Close() error {
	if c.cleanup != nil {
		c.cleanup()
	}
	return c.Conn.Close()
}

func (c *selfBypassConn) SyscallConn() (syscall.RawConn, error) { return c.rawConn, nil }

type selfBypassPacketConn struct {
	net.PacketConn
	cleanup func()
	rawConn syscall.RawConn
}

func (c *selfBypassPacketConn) Close() error {
	if c.cleanup != nil {
		c.cleanup()
	}
	return c.PacketConn.Close()
}

func (c *selfBypassPacketConn) SyscallConn() (syscall.RawConn, error) { return c.rawConn, nil }

// EBPFSelfBypassCleanup returns an idempotent cleanup callback for a socket
// registered by AppendEBPFSelfBypass. External socket owners should invoke it
// immediately before closing the socket when the runtime has no kernel release
// hook, such as Tailscale's custom packet listener path.
func EBPFSelfBypassCleanup(networkManager adapter.NetworkManager, rawConn syscall.RawConn) func() {
	provider, loaded := networkManager.(interface {
		EBPFSelfBypass() *commonEBPF.SelfBypass
	})
	if !loaded {
		return nil
	}
	tracker := provider.EBPFSelfBypass()
	if tracker == nil || tracker.CleanupMode() != "lru_fallback" {
		return nil
	}
	var once sync.Once
	return func() {
		once.Do(func() { _ = tracker.UnregisterSocket(rawConn) })
	}
}

func PrepareEBPFSelfBypass(networkManager adapter.NetworkManager, inbounds []option.Inbound, scope *adapter.Scope) error {
	localInstances := 0
	for _, inbound := range inbounds {
		switch inbound.Type {
		case C.TypeEBPF:
			ebpfOptions, loaded := inbound.Options.(*option.EBPFInboundOptions)
			if !loaded {
				return E.New("invalid eBPF inbound options")
			}
			localEnabled, _ := ebpfOptions.EffectiveEnablement()
			if localEnabled {
				localInstances++
			}
		}
	}
	if localInstances > 1 {
		return E.New("only one local or hybrid eBPF inbound is supported")
	}
	if localInstances == 0 {
		return nil
	}
	if scope == nil {
		return E.New("missing eBPF self-bypass lifecycle scope")
	}
	var tracker *commonEBPF.SelfBypass
	var err error
	if runtime.GOOS == "android" {
		tracker, err = commonEBPF.NewSelfBypassWithCapacity(commonEBPF.CompactSelfBypassSocketCapacity)
	} else {
		tracker, err = commonEBPF.NewSelfBypass()
	}
	if err != nil {
		return err
	}
	setter, loaded := networkManager.(interface {
		SetEBPFSelfBypass(*commonEBPF.SelfBypass) error
	})
	if !loaded {
		_ = tracker.Close()
		return E.New("network manager does not support eBPF self-bypass sockets")
	}
	if err = setter.SetEBPFSelfBypass(tracker); err != nil {
		_ = tracker.Close()
		return err
	}
	// Preparation allocates a kernel map before any inbound is started.
	// Retain a fallback owner for constructor failures and unstarted boxes.
	scope.Add(func() error {
		if clearer, loaded := networkManager.(interface {
			ClearEBPFSelfBypass(*commonEBPF.SelfBypass)
		}); loaded {
			clearer.ClearEBPFSelfBypass(tracker)
		}
		return tracker.Close()
	})
	return nil
}

// AppendEBPFSelfBypass appends the eBPF self-bypass registration callback to a
// socket control chain. It is also used by integrations that create sockets
// outside DefaultDialer, such as endpoint-specific network stacks.
func AppendEBPFSelfBypass(networkManager adapter.NetworkManager, controlFunc control.Func) control.Func {
	provider, loaded := networkManager.(interface {
		EBPFSelfBypass() *commonEBPF.SelfBypass
	})
	if !loaded {
		return controlFunc
	}
	selfBypassFunc := func(_ string, _ string, rawConn syscall.RawConn) error {
		tracker := provider.EBPFSelfBypass()
		if tracker == nil {
			return nil
		}
		return tracker.RegisterSocket(rawConn)
	}
	return control.Append(controlFunc, selfBypassFunc)
}

func appendEBPFSelfBypass(networkManager adapter.NetworkManager, dialerControl, listenerControl control.Func) (control.Func, control.Func) {
	return AppendEBPFSelfBypass(networkManager, dialerControl), AppendEBPFSelfBypass(networkManager, listenerControl)
}
