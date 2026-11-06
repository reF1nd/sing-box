//go:build with_ebpf && (linux || android)

package dialer

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	commonEBPF "github.com/CHIZI-0618/sing-ebpf"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/control"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"

	"github.com/database64128/tfo-go/v2"
)

type halfCloseTestConn struct {
	net.Conn
	readClosed, writeClosed bool
	closes                  int
}

func (c *halfCloseTestConn) CloseRead() error  { c.readClosed = true; return nil }
func (c *halfCloseTestConn) CloseWrite() error { c.writeClosed = true; return nil }
func (c *halfCloseTestConn) Close() error      { c.closes++; return nil }

func TestSelfBypassPreservesHalfClose(t *testing.T) {
	underlying := &halfCloseTestConn{}
	cleanups := 0
	wrapped := &selfBypassConn{Conn: underlying, cleanup: func() { cleanups++ }}
	if err := N.CloseWrite(wrapped); err != nil {
		t.Fatal(err)
	}
	if err := N.CloseRead(wrapped); err != nil {
		t.Fatal(err)
	}
	if !underlying.writeClosed || !underlying.readClosed || cleanups != 0 || underlying.closes != 0 {
		t.Fatal("half close must reach the socket without unregistering it")
	}
	if N.UnwrapReader(wrapped) != underlying || N.UnwrapWriter(wrapped) != underlying {
		t.Fatal("I/O capabilities must remain accessible")
	}
	var wait sync.WaitGroup
	for range 8 {
		wait.Go(func() { _ = wrapped.Close() })
	}
	wait.Wait()
	if cleanups != 1 || underlying.closes != 1 {
		t.Fatal("full close must run exactly once")
	}
}

type noSelfBypassNetworkManager struct{ adapter.NetworkManager }

func (noSelfBypassNetworkManager) EBPFSelfBypass() *commonEBPF.SelfBypass { return nil }

func TestSelfBypassWithoutLocalInboundIsInert(t *testing.T) {
	if AppendEBPFSelfBypass(noSelfBypassNetworkManager{}, nil) != nil {
		t.Fatal("no tracker must mean no socket control callback")
	}
}

func TestSelfBypassLifecycleContract(t *testing.T) {
	tracker, err := commonEBPF.NewSelfBypassWithCapacity(1)
	if err != nil {
		t.Fatal(err)
	}
	defer tracker.Close()
	if !tracker.NeedsUserspaceRegistration() || !tracker.NeedsUserspaceUnregister() {
		t.Fatal("userspace producer must own registration and cleanup")
	}
}

func TestAppendDialerControlPreservesControlContext(t *testing.T) {
	var order []string
	dialer := &net.Dialer{
		ControlContext: func(context.Context, string, string, syscall.RawConn) error {
			order = append(order, "base")
			return nil
		},
	}
	appendDialerControl(dialer, func(string, string, syscall.RawConn) error {
		order = append(order, "extra")
		return nil
	})
	if err := dialer.ControlContext(context.Background(), "tcp", "127.0.0.1:1", nil); err != nil {
		t.Fatal(err)
	}
	if len(order) != 2 || order[0] != "extra" || order[1] != "base" {
		t.Fatalf("unexpected control order: %v", order)
	}

	bindErr := errors.New("bind failed")
	baseCalled := false
	dialer.ControlContext = func(context.Context, string, string, syscall.RawConn) error {
		baseCalled = true
		return nil
	}
	appendDialerControl(dialer, func(string, string, syscall.RawConn) error { return bindErr })
	if err := dialer.ControlContext(context.Background(), "tcp", "127.0.0.1:1", nil); !errors.Is(err, bindErr) {
		t.Fatalf("unexpected control error: %v", err)
	}
	if baseCalled {
		t.Fatal("base control must not register self-bypass after interface binding fails")
	}
}

func TestUDPListenerControlIncludesUserspaceSelfBypass(t *testing.T) {
	tracker, err := commonEBPF.NewSelfBypassWithCapacity(1)
	if err != nil {
		t.Fatal(err)
	}
	defer tracker.Close()

	dialer := &DefaultDialer{networkManager: &selfBypassTestNetworkManager{tracker: tracker}}
	listenerControl, _ := dialer.UDPListenerControl()
	if listenerControl == nil {
		t.Fatal("external UDP listeners need a self-bypass control")
	}
	if dialer.udpListener.Control != nil {
		t.Fatal("ordinary UDP listeners should still register after bind")
	}
}

type selfBypassTestNetworkManager struct {
	adapter.NetworkManager
	tracker *commonEBPF.SelfBypass
}

func (m *selfBypassTestNetworkManager) EBPFSelfBypass() *commonEBPF.SelfBypass {
	return m.tracker
}

func (*selfBypassTestNetworkManager) InterfaceFinder() control.InterfaceFinder {
	return nil
}

func (*selfBypassTestNetworkManager) DefaultOptions() adapter.NetworkOptions {
	return adapter.NetworkOptions{}
}

func (*selfBypassTestNetworkManager) AutoDetectInterface() bool {
	return false
}

func (*selfBypassTestNetworkManager) DefaultInterface() string {
	return ""
}

func (*selfBypassTestNetworkManager) AutoDetectInterfaceFunc() control.Func {
	return nil
}

func (*selfBypassTestNetworkManager) AutoRedirectOutputMarkFunc() control.Func {
	return nil
}

func (*selfBypassTestNetworkManager) ProtectFunc() control.Func {
	return nil
}

func (*selfBypassTestNetworkManager) DefaultOutboundInterface() string {
	return ""
}

func (*selfBypassTestNetworkManager) NetworkInterfaces() []adapter.NetworkInterface {
	return nil
}

func requireBPFPrivilegeOrSkip(t *testing.T, tracker *commonEBPF.SelfBypass) {
	t.Helper()
	probeConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer probeConn.Close()
	rawConn, err := probeConn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	reg, err := tracker.RegisterSocket(rawConn)
	if err != nil {
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.ENOSYS) {
			t.Skipf("requires CAP_BPF/CAP_SYS_ADMIN: %v", err)
		}
		t.Fatalf("failed to probe self-bypass BPF map creation: %v", err)
	}
	if err = tracker.UnregisterSocket(reg); err != nil {
		t.Fatalf("failed to unregister initial probe socket: %v", err)
	}
}

func assertTrackerCapacitySlot(t *testing.T, tracker *commonEBPF.SelfBypass, wantFree bool) {
	t.Helper()
	before := tracker.Diagnostics()
	probeConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer probeConn.Close()
	rawConn, err := probeConn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	reg, err := tracker.RegisterSocket(rawConn)
	if wantFree {
		if err != nil {
			t.Fatalf("expected free self-bypass slot, got registration error: %v", err)
		}
		if err = tracker.UnregisterSocket(reg); err != nil {
			t.Fatalf("failed to unregister probe socket: %v", err)
		}
		after := tracker.Diagnostics()
		if after.ReclaimAttempts != before.ReclaimAttempts || after.ReclaimedSockets != before.ReclaimedSockets {
			t.Fatalf(
				"expected direct userspace unregister without E2BIG reclaim: attempts %d->%d, reclaimed %d->%d",
				before.ReclaimAttempts, after.ReclaimAttempts, before.ReclaimedSockets, after.ReclaimedSockets,
			)
		}
		return
	}
	if err == nil {
		_ = tracker.UnregisterSocket(reg)
		t.Fatal("expected capacity-1 self-bypass tracker to be full while lazy TFO conn is open")
	}
	if !errors.Is(err, syscall.E2BIG) {
		t.Fatalf("expected E2BIG when capacity-1 self-bypass tracker is full, got: %v", err)
	}
}

func TestDefaultDialerLazyTFOSelfBypassLifecycle(t *testing.T) {
	tracker, err := commonEBPF.NewSelfBypassWithCapacity(1)
	if err != nil {
		t.Fatal(err)
	}
	defer tracker.Close()
	requireBPFPrivilegeOrSkip(t, tracker)

	networkManager := &selfBypassTestNetworkManager{tracker: tracker}
	ctx := service.ContextWith[adapter.NetworkManager](context.Background(), networkManager)
	dialer, err := NewDefault(ctx, option.DialerOptions{
		AbstractDialerOptions: option.AbstractDialerOptions{
			TCPFastOpen: true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	// 1. Success path: lazy connect on first write, registered while open, unregistered on close.
	ln, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	const wantPayload = "tfo-first-write"
	accepted := make(chan struct{}, 1)
	serverPayload := make(chan string, 1)
	go func() {
		srvConn, acceptErr := ln.AcceptTCP()
		if acceptErr != nil {
			return
		}
		defer srvConn.Close()
		accepted <- struct{}{}
		buf := make([]byte, len(wantPayload))
		if _, readErr := io.ReadFull(srvConn, buf); readErr == nil {
			serverPayload <- string(buf)
			_, _ = srvConn.Write([]byte("pong"))
		}
	}()

	dest := M.SocksaddrFromNet(ln.Addr())
	conn, err := dialer.DialContext(ctx, N.NetworkTCP, dest)
	if err != nil {
		t.Fatal(err)
	}
	if !N.NeedHandshakeForWrite(conn) {
		_ = conn.Close()
		t.Fatal("expected lazy TFO slowOpenConn when userspace self-bypass is active")
	}
	select {
	case <-accepted:
		_ = conn.Close()
		t.Fatal("lazy TFO must not connect before the first Write")
	case <-time.After(30 * time.Millisecond):
	}
	assertTrackerCapacitySlot(t, tracker, true)

	written, err := conn.Write([]byte(wantPayload))
	if err != nil || written != len(wantPayload) {
		_ = conn.Close()
		t.Fatalf("lazy TFO first write failed: n=%d err=%v", written, err)
	}
	select {
	case got := <-serverPayload:
		if got != wantPayload {
			_ = conn.Close()
			t.Fatalf("unexpected first write payload: %q", got)
		}
	case <-time.After(2 * time.Second):
		_ = conn.Close()
		t.Fatal("timed out waiting for lazy TFO first payload")
	}
	// While open, the single slot in capacity-1 tracker must be occupied by this socket.
	assertTrackerCapacitySlot(t, tracker, false)

	reply := make([]byte, 4)
	if _, err = io.ReadFull(conn, reply); err != nil {
		_ = conn.Close()
		t.Fatalf("read reply failed: %v", err)
	}
	if string(reply) != "pong" {
		_ = conn.Close()
		t.Fatalf("unexpected reply: %q", string(reply))
	}
	if err = conn.Close(); err != nil {
		t.Fatalf("close lazy TFO conn failed: %v", err)
	}
	// Closing must unregister the socket cookie immediately.
	assertTrackerCapacitySlot(t, tracker, true)

	// 2. Dial failure path: failed lazy Write must report 0 bytes written and unregister any socket cookie.
	deadLn, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	deadAddr := M.SocksaddrFromNet(deadLn.Addr())
	_ = deadLn.Close()

	failConn, err := dialer.DialContext(ctx, N.NetworkTCP, deadAddr)
	if err != nil {
		t.Fatal(err)
	}
	if !N.NeedHandshakeForWrite(failConn) {
		_ = failConn.Close()
		t.Fatal("expected lazy TFO conn on dial failure test")
	}
	if n, writeErr := failConn.Write([]byte("fail")); writeErr == nil || n != 0 {
		_ = failConn.Close()
		t.Fatalf("expected dial error with n=0 on closed port, got n=%d err=%v", n, writeErr)
	}
	_ = failConn.Close()
	assertTrackerCapacitySlot(t, tracker, true)

	// 3. Close-before-Write path: must not leak or panic.
	earlyConn, err := dialer.DialContext(ctx, N.NetworkTCP, dest)
	if err != nil {
		t.Fatal(err)
	}
	if err = earlyConn.Close(); err != nil {
		t.Fatal(err)
	}
	if n, writeErr := earlyConn.Write([]byte("after-close")); !errors.Is(writeErr, os.ErrClosed) || n != 0 {
		t.Fatalf("expected (0, os.ErrClosed) after early close, got n=%d err=%v", n, writeErr)
	}
	assertTrackerCapacitySlot(t, tracker, true)
}

func TestSlowOpenConnCloseDuringDialUnregistersOnce(t *testing.T) {
	ln, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	const wantPayload = "payload"
	serverReceived := make(chan string, 1)
	go func() {
		srvConn, acceptErr := ln.AcceptTCP()
		if acceptErr != nil {
			return
		}
		defer srvConn.Close()
		buf := make([]byte, len(wantPayload))
		if _, readErr := io.ReadFull(srvConn, buf); readErr == nil {
			serverReceived <- string(buf)
		}
	}()

	inDial := make(chan struct{})
	releaseDial := make(chan struct{})
	closeHandlerEntered := make(chan struct{})
	releaseCloseHandler := make(chan struct{})
	var dialTCPConn atomic.Pointer[net.TCPConn]
	dialCtx, cancel := context.WithCancel(context.Background())
	conn := &slowOpenConn{
		ctx:         dialCtx,
		cancel:      cancel,
		network:     N.NetworkTCP,
		destination: M.SocksaddrFromNet(ln.Addr()),
		create:      make(chan struct{}),
		done:        make(chan struct{}),
		dialFunc: func(_ context.Context, _ *tfo.Dialer, network string, address string, payload []byte) (net.Conn, error) {
			c, dialErr := net.Dial(network, address)
			if dialErr != nil {
				return nil, dialErr
			}
			if _, writeErr := c.Write(payload); writeErr != nil {
				_ = c.Close()
				return nil, writeErr
			}
			dialTCPConn.Store(c.(*net.TCPConn))
			close(inDial)
			<-releaseDial
			return c, nil
		},
	}

	var closeCalls atomic.Int32
	conn.setCloseHandler(func(*net.TCPConn) {
		if closeCalls.Add(1) == 1 {
			close(closeHandlerEntered)
			<-releaseCloseHandler
		}
	})

	type writeResult struct {
		n   int
		err error
	}
	writeResCh := make(chan writeResult, 1)
	go func() {
		n, writeErr := conn.Write([]byte(wantPayload))
		writeResCh <- writeResult{n: n, err: writeErr}
	}()

	select {
	case <-inDial:
	case res := <-writeResCh:
		t.Fatalf("Write exited before entering dialFunc: n=%d err=%v", res.n, res.err)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for Write to enter dialFunc")
	}

	select {
	case got := <-serverReceived:
		if got != wantPayload {
			close(releaseDial)
			close(releaseCloseHandler)
			t.Fatalf("unexpected payload received by server: %q", got)
		}
	case <-time.After(2 * time.Second):
		close(releaseDial)
		close(releaseCloseHandler)
		t.Fatal("timed out waiting for server to receive initial payload")
	}

	if err = conn.Close(); err != nil {
		close(releaseDial)
		close(releaseCloseHandler)
		t.Fatal(err)
	}
	close(releaseDial)

	select {
	case <-closeHandlerEntered:
	case <-time.After(2 * time.Second):
		close(releaseCloseHandler)
		t.Fatal("timed out waiting for closeHandler to run")
	}

	// While closeHandler is paused before closing the underlying fd,
	// slowOpenConn must not have published TCPConn after Close() returned.
	if published := conn.conn.Load(); published != nil {
		close(releaseCloseHandler)
		t.Fatal("slowOpenConn published TCPConn after Close() returned")
	}

	afterWriteRes := make(chan writeResult, 1)
	go func() {
		n, writeErr := conn.Write([]byte("after-close"))
		afterWriteRes <- writeResult{n: n, err: writeErr}
	}()
	close(releaseCloseHandler)

	select {
	case res := <-writeResCh:
		if !errors.Is(res.err, os.ErrClosed) || res.n != len(wantPayload) {
			t.Fatalf("expected (%d, os.ErrClosed) from initial Write, got n=%d err=%v", len(wantPayload), res.n, res.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for initial Write to return")
	}
	select {
	case res := <-afterWriteRes:
		if !errors.Is(res.err, os.ErrClosed) || res.n != 0 {
			t.Fatalf("expected (0, os.ErrClosed) from post-Close Write, got n=%d err=%v", res.n, res.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for post-Close Write to return")
	}

	if err = conn.Close(); err != nil {
		t.Fatal(err)
	}
	if got := closeCalls.Load(); got != 1 {
		t.Fatalf("expected close handler to run exactly once, got %d", got)
	}
	tcpConn := dialTCPConn.Load()
	if tcpConn == nil {
		t.Fatal("expected dialFunc to produce TCPConn")
	}
	if _, err = tcpConn.Write([]byte("x")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("expected underlying TCPConn to be closed, got %v", err)
	}
	// Also verify closeTCP directly is idempotent under repeated calls.
	conn.closeTCP(tcpConn)
	if got := closeCalls.Load(); got != 1 {
		t.Fatalf("expected closeTCP to remain idempotent, got %d", got)
	}
}

func TestSlowOpenConnWriteToOnCloseReturnsClosed(t *testing.T) {
	dialCtx, cancel := context.WithCancel(context.Background())
	conn := &slowOpenConn{
		ctx:     dialCtx,
		cancel:  cancel,
		network: N.NetworkTCP,
		create:  make(chan struct{}),
		done:    make(chan struct{}),
		dialFunc: func(ctx context.Context, _ *tfo.Dialer, _ string, _ string, _ []byte) (net.Conn, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}

	writeDone := make(chan error, 1)
	go func() {
		_, err := conn.Write([]byte("trigger-dial"))
		writeDone <- err
	}()

	writeToRes := make(chan struct {
		n   int64
		err error
	}, 1)
	go func() {
		n, err := conn.WriteTo(io.Discard)
		writeToRes <- struct {
			n   int64
			err error
		}{n: n, err: err}
	}()

	time.Sleep(10 * time.Millisecond)
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}

	select {
	case res := <-writeToRes:
		if res.n != 0 || res.err == nil {
			t.Fatalf("expected non-nil error and n=0 from WriteTo on Close, got n=%d err=%v", res.n, res.err)
		}
		if !errors.Is(res.err, os.ErrClosed) && !errors.Is(res.err, context.Canceled) {
			t.Fatalf("expected os.ErrClosed or context.Canceled from WriteTo, got %v", res.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for WriteTo to exit after Close")
	}
	select {
	case err := <-writeDone:
		if err == nil {
			t.Fatal("expected Write to fail after Close")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for Write to exit after Close")
	}

	// Pure Close-before-Write WriteTo must return os.ErrClosed deterministically.
	dialCtx2, cancel2 := context.WithCancel(context.Background())
	conn2 := &slowOpenConn{
		ctx:     dialCtx2,
		cancel:  cancel2,
		network: N.NetworkTCP,
		create:  make(chan struct{}),
		done:    make(chan struct{}),
	}
	if err := conn2.Close(); err != nil {
		t.Fatal(err)
	}
	if n, err := conn2.WriteTo(io.Discard); n != 0 || !errors.Is(err, os.ErrClosed) {
		t.Fatalf("expected (0, os.ErrClosed) from WriteTo after Close, got n=%d err=%v", n, err)
	}
}
