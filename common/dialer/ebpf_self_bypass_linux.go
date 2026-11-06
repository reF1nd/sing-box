//go:build with_ebpf && (linux || android)

package dialer

import (
	"context"
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
	if !tracker.NeedsUserspaceUnregister() {
		return conn
	}
	if lazyConn, loaded := conn.(*slowOpenConn); loaded {
		lazyConn.setCloseHandler(func(tcpConn *net.TCPConn) {
			rawConn, err := tcpConn.SyscallConn()
			if err == nil {
				if cookie, cookieErr := tracker.SocketCookie(rawConn); cookieErr == nil {
					_ = tracker.UnregisterSocket(commonEBPF.SocketRegistration{Cookie: cookie})
				}
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
	if !tracker.NeedsUserspaceUnregister() {
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

// RegisterEBPFSelfBypassPacketConn records a successfully created packet
// socket. Callers must invoke this after ListenPacket succeeds: a
// net.ListenConfig control callback runs before bind and cannot unregister a
// cookie when the bind fails.
func RegisterEBPFSelfBypassPacketConn(networkManager adapter.NetworkManager, conn net.PacketConn) error {
	provider, loaded := networkManager.(interface {
		EBPFSelfBypass() *commonEBPF.SelfBypass
	})
	if !loaded || provider.EBPFSelfBypass() == nil {
		return nil
	}
	syscallConn, loaded := conn.(syscall.Conn)
	if !loaded {
		return nil
	}
	rawConn, err := syscallConn.SyscallConn()
	if err != nil {
		return err
	}
	_, err = provider.EBPFSelfBypass().RegisterSocket(rawConn)
	return err
}

type selfBypassConn struct {
	net.Conn
	cleanup   func()
	rawConn   syscall.RawConn
	closeOnce sync.Once
	closeErr  error
}

func (c *selfBypassConn) Close() error {
	c.closeOnce.Do(func() {
		if c.cleanup != nil {
			c.cleanup()
		}
		c.closeErr = c.Conn.Close()
	})
	return c.closeErr
}

func (c *selfBypassConn) SyscallConn() (syscall.RawConn, error) { return c.rawConn, nil }

// Only I/O may unwrap this adapter. The original owner must still close the
// wrapper to unregister the cookie before the socket FD is released.
func (c *selfBypassConn) Upstream() any           { return c.Conn }
func (c *selfBypassConn) ReaderReplaceable() bool { return true }
func (c *selfBypassConn) WriterReplaceable() bool { return true }

type selfBypassPacketConn struct {
	net.PacketConn
	cleanup   func()
	rawConn   syscall.RawConn
	closeOnce sync.Once
	closeErr  error
}

func (c *selfBypassPacketConn) Close() error {
	c.closeOnce.Do(func() {
		if c.cleanup != nil {
			c.cleanup()
		}
		c.closeErr = c.PacketConn.Close()
	})
	return c.closeErr
}

func (c *selfBypassPacketConn) SyscallConn() (syscall.RawConn, error) { return c.rawConn, nil }

func (c *selfBypassPacketConn) Upstream() any           { return c.PacketConn }
func (c *selfBypassPacketConn) ReaderReplaceable() bool { return true }
func (c *selfBypassPacketConn) WriterReplaceable() bool { return true }

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
	if tracker == nil || !tracker.NeedsUserspaceUnregister() {
		return nil
	}
	// Read the cookie before returning the callback. The socket may be closed
	// through another reference before the owner invokes this callback.
	cookie, err := tracker.SocketCookie(rawConn)
	if err != nil {
		return nil
	}
	var once sync.Once
	return func() {
		once.Do(func() { _ = tracker.UnregisterSocket(commonEBPF.SocketRegistration{Cookie: cookie}) })
	}
}

type selfBypassDialAttemptKey struct{}

type selfBypassDialAttempt struct {
	tracker *commonEBPF.SelfBypass
	access  sync.Mutex
	pending map[uint64]commonEBPF.SocketRegistration
	done    bool
}

var errSelfBypassDialDone = E.New("eBPF self-bypass dial attempt already finished")

func newSelfBypassDialAttempt(tracker *commonEBPF.SelfBypass) *selfBypassDialAttempt {
	return &selfBypassDialAttempt{tracker: tracker, pending: make(map[uint64]commonEBPF.SocketRegistration)}
}

func (a *selfBypassDialAttempt) register(rawConn syscall.RawConn) error {
	registration, err := a.tracker.RegisterSocket(rawConn)
	if err != nil {
		return err
	}
	if !registration.Active() {
		return nil
	}
	a.access.Lock()
	if a.done {
		a.access.Unlock()
		_ = a.tracker.UnregisterSocket(registration)
		return errSelfBypassDialDone
	}
	a.pending[registration.Cookie] = registration
	a.access.Unlock()
	return nil
}

// commit keeps the returned connection registered. It reports false when the
// winner cannot be identified, in which case cleanup must not run.
func (a *selfBypassDialAttempt) commit(conn net.Conn) bool {
	if conn == nil {
		return false
	}
	syscallConn, loaded := conn.(syscall.Conn)
	if !loaded {
		return false
	}
	rawConn, err := syscallConn.SyscallConn()
	if err != nil {
		return false
	}
	cookie, err := a.tracker.SocketCookie(rawConn)
	if err != nil {
		return false
	}
	a.access.Lock()
	delete(a.pending, cookie)
	a.access.Unlock()
	return true
}

func (a *selfBypassDialAttempt) cleanup() {
	a.access.Lock()
	a.done = true
	pending := make([]commonEBPF.SocketRegistration, 0, len(a.pending))
	for _, registration := range a.pending {
		pending = append(pending, registration)
	}
	clear(a.pending)
	a.access.Unlock()
	for _, registration := range pending {
		_ = a.tracker.UnregisterSocket(registration)
	}
}

func selfBypassDialAttemptFromContext(ctx context.Context) *selfBypassDialAttempt {
	if ctx == nil {
		return nil
	}
	attempt, _ := ctx.Value(selfBypassDialAttemptKey{}).(*selfBypassDialAttempt)
	return attempt
}

func appendEBPFSelfBypassDialer(networkManager adapter.NetworkManager, dialer *net.Dialer) {
	provider, loaded := networkManager.(interface {
		EBPFSelfBypass() *commonEBPF.SelfBypass
	})
	if !loaded || provider.EBPFSelfBypass() == nil {
		return
	}
	tracker := provider.EBPFSelfBypass()
	baseControl := dialer.Control
	baseControlContext := dialer.ControlContext
	dialer.ControlContext = func(ctx context.Context, network, address string, rawConn syscall.RawConn) error {
		if baseControlContext != nil {
			if err := baseControlContext(ctx, network, address, rawConn); err != nil {
				return err
			}
		} else if baseControl != nil {
			if err := baseControl(network, address, rawConn); err != nil {
				return err
			}
		}
		if attempt := selfBypassDialAttemptFromContext(ctx); attempt != nil {
			return attempt.register(rawConn)
		}
		if !tracker.NeedsUserspaceRegistration() {
			return nil
		}
		_, err := tracker.RegisterSocket(rawConn)
		return err
	}
}

func (d *DefaultDialer) selfBypassTracker() *commonEBPF.SelfBypass {
	if d.networkManager == nil {
		return nil
	}
	provider, loaded := d.networkManager.(interface {
		EBPFSelfBypass() *commonEBPF.SelfBypass
	})
	if !loaded {
		return nil
	}
	tracker := provider.EBPFSelfBypass()
	if tracker == nil {
		return nil
	}
	if !tracker.NeedsUserspaceRegistration() {
		return nil
	}
	return tracker
}

func (d *DefaultDialer) dialWithSelfBypass(ctx context.Context, dialer net.Dialer, network, address string) (net.Conn, error) {
	tracker := d.selfBypassTracker()
	if tracker == nil {
		return dialer.DialContext(ctx, network, address)
	}
	attempt := newSelfBypassDialAttempt(tracker)
	dialContext := context.WithValue(ctx, selfBypassDialAttemptKey{}, attempt)
	conn, err := dialer.DialContext(dialContext, network, address)
	if err != nil {
		attempt.cleanup()
		return conn, err
	}
	if attempt.commit(conn) {
		attempt.cleanup()
	}
	return conn, nil
}

// CloseUnclaimedEBPFSelfBypass releases a prepared self-bypass that no eBPF
// inbound claimed during initialization. The box registers it at construction,
// so it runs last when the box closes.
func CloseUnclaimedEBPFSelfBypass(networkManager adapter.NetworkManager) error {
	closer, loaded := networkManager.(interface {
		CloseUnclaimedEBPFSelfBypass() error
	})
	if !loaded {
		return nil
	}
	return closer.CloseUnclaimedEBPFSelfBypass()
}

func PrepareEBPFSelfBypass(networkManager adapter.NetworkManager, inbounds []option.Inbound) error {
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
	return nil
}

// AppendEBPFSelfBypass appends the eBPF self-bypass registration callback to a
// socket control chain. It is also used by integrations that create sockets
// outside DefaultDialer, such as endpoint-specific network stacks.
func AppendEBPFSelfBypass(networkManager adapter.NetworkManager, controlFunc control.Func) control.Func {
	provider, loaded := networkManager.(interface {
		EBPFSelfBypass() *commonEBPF.SelfBypass
	})
	if !loaded || provider.EBPFSelfBypass() == nil {
		return controlFunc
	}
	tracker := provider.EBPFSelfBypass()
	selfBypassFunc := func(_ string, _ string, rawConn syscall.RawConn) error {
		if !tracker.NeedsUserspaceRegistration() {
			return nil
		}
		_, err := tracker.RegisterSocket(rawConn)
		return err
	}
	return control.Append(controlFunc, selfBypassFunc)
}

func appendEBPFSelfBypass(networkManager adapter.NetworkManager, dialerControl, listenerControl control.Func) (control.Func, control.Func) {
	return AppendEBPFSelfBypass(networkManager, dialerControl), AppendEBPFSelfBypass(networkManager, listenerControl)
}
