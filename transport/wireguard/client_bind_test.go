package wireguard

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"
	"github.com/sagernet/wireguard-go/conn"
	"github.com/sagernet/wireguard-go/device"
	wgTun "github.com/sagernet/wireguard-go/tun"
)

func TestClientBindCloseUnblocksPausedReceive(t *testing.T) {
	pauseManager := newTestPauseManager()
	bind := NewClientBind(context.Background(), logger.NOP(), failingDialer{}, M.ParseSocksaddr("127.0.0.1:1"), [3]uint8{})
	bind.pauseManager = pauseManager
	fns, _, err := bind.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer pauseManager.Resume()

	receiveErr := make(chan error, 1)
	go func() {
		_, err := fns[0](make([]byte, 2048), make([]conn.ReceivedPacket, 1))
		receiveErr <- err
	}()

	select {
	case <-pauseManager.waiting:
	case <-time.After(time.Second):
		t.Fatal("receive did not wait for an active network")
	}
	if err = bind.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-receiveErr:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("expected net.ErrClosed, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("receive did not exit after bind close")
	}
}

func TestClientBindCloseDoesNotWaitForDial(t *testing.T) {
	dialer := newBlockingDialer()
	bind := NewClientBind(context.Background(), logger.NOP(), dialer, M.ParseSocksaddr("127.0.0.1:1"), [3]uint8{})
	fns, _, err := bind.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer dialer.Release()

	receiveErr := make(chan error, 1)
	go func() {
		_, err := fns[0](make([]byte, 2048), make([]conn.ReceivedPacket, 1))
		receiveErr <- err
	}()

	select {
	case <-dialer.started:
	case <-time.After(time.Second):
		t.Fatal("dial did not start")
	}
	closeDone := make(chan struct{})
	go func() {
		_ = bind.Close()
		close(closeDone)
	}()
	select {
	case <-closeDone:
	case <-time.After(time.Second):
		t.Fatal("bind close waited for dial")
	}

	dialer.Release()
	select {
	case err := <-receiveErr:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("expected net.ErrClosed, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("receive did not exit after dial returned")
	}
}

func TestClientBindReopenIsolatesStaleGeneration(t *testing.T) {
	dialer := newBlockingDialer()
	staleConn := &trackingPacketConn{}
	dialer.conn = staleConn
	bind := NewClientBind(context.Background(), logger.NOP(), dialer, M.ParseSocksaddr("127.0.0.1:1"), [3]uint8{})
	fns1, _, err := bind.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer bind.Close()
	defer dialer.Release()

	receiveErr := make(chan error, 1)
	go func() {
		_, err := fns1[0](make([]byte, 2048), make([]conn.ReceivedPacket, 1))
		receiveErr <- err
	}()

	select {
	case <-dialer.started:
	case <-time.After(time.Second):
		t.Fatal("listen did not start")
	}
	if err := bind.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := bind.Open(0); err != nil {
		t.Fatal(err)
	}
	dialer.Release()
	select {
	case err := <-receiveErr:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("stale generation receive expected net.ErrClosed, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("stale generation receive did not exit")
	}
	if !staleConn.closed.Load() {
		t.Fatal("stale socket from previous generation was not closed")
	}
	if bind.conn.Load() != nil {
		t.Fatal("stale socket leaked into reopened generation")
	}
}

func TestClientBindNetworkWakeSkipsRetryDelay(t *testing.T) {
	pauseManager := newTestPauseManager()
	bind := NewClientBind(context.Background(), logger.NOP(), failingDialer{}, M.ParseSocksaddr("127.0.0.1:1"), [3]uint8{})
	bind.pauseManager = pauseManager
	waitDone := make(chan bool, 1)
	go func() {
		waitDone <- bind.waitAfterFailure(bind.currentDone())
	}()

	select {
	case <-pauseManager.waiting:
	case <-time.After(time.Second):
		t.Fatal("bind did not wait for network wake")
	}
	wakeTime := time.Now()
	pauseManager.Resume()
	select {
	case resumed := <-waitDone:
		if !resumed {
			t.Fatal("bind wait was canceled")
		}
		if elapsed := time.Since(wakeTime); elapsed >= clientBindRetryInterval/2 {
			t.Fatalf("network wake retained retry delay: %v", elapsed)
		}
	case <-time.After(clientBindRetryInterval / 2):
		t.Fatal("bind retained retry delay after network wake")
	}
}

func TestEndpointWaitNetworkActive(t *testing.T) {
	pauseManager := newEndpointPauseManager()
	endpoint := &Endpoint{
		options:      EndpointOptions{Context: context.Background()},
		pause:        pauseManager,
		pauseUpdated: make(chan struct{}),
		done:         make(chan struct{}),
	}
	endpoint.pauseCallback = pauseManager.RegisterCallback(endpoint.onPauseUpdated)
	waitDone := make(chan error, 1)
	go func() {
		waitDone <- endpoint.waitNetworkActive(context.Background())
	}()

	select {
	case <-pauseManager.waiting:
	case <-time.After(time.Second):
		t.Fatal("network wait did not start")
	}
	pauseManager.Resume()
	select {
	case err := <-waitDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("wait did not exit after network wake")
	}
}

func TestEndpointCloseUnblocksNetworkWait(t *testing.T) {
	pauseManager := newEndpointPauseManager()
	endpoint := &Endpoint{
		options:      EndpointOptions{Context: context.Background()},
		pause:        pauseManager,
		pauseUpdated: make(chan struct{}),
		done:         make(chan struct{}),
	}
	endpoint.pauseCallback = pauseManager.RegisterCallback(endpoint.onPauseUpdated)
	waitDone := make(chan error, 1)
	go func() {
		waitDone <- endpoint.waitNetworkActive(context.Background())
	}()

	select {
	case <-pauseManager.waiting:
	case <-time.After(time.Second):
		t.Fatal("network wait did not start")
	}
	if err := endpoint.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-waitDone:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("expected closed error, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("wait did not exit after endpoint close")
	}
}

func TestClientBindSendDoesNotBlockWhenPaused(t *testing.T) {
	pauseManager := newTestPauseManager()
	bind := NewClientBind(context.Background(), logger.NOP(), failingDialer{}, M.ParseSocksaddr("127.0.0.1:1"), [3]uint8{})
	bind.pauseManager = pauseManager
	if _, _, err := bind.Open(0); err != nil {
		t.Fatal(err)
	}
	defer bind.Close()
	defer pauseManager.Resume()

	ep, err := bind.ParseEndpoint("127.0.0.1:51820")
	if err != nil {
		t.Fatal(err)
	}
	sendDone := make(chan error, 1)
	go func() {
		sendDone <- bind.Send([][]byte{make([]byte, 32)}, ep, 0)
	}()

	select {
	case err := <-sendDone:
		if err == nil {
			t.Fatal("expected send error from failing dialer")
		}
	case <-time.After(time.Second):
		t.Fatal("Send blocked while network was paused")
	}
}

func TestEndpointCloseDoesNotDeadlockDuringClientBindSend(t *testing.T) {
	ctx := pause.WithDefaultManager(context.Background())
	pauseManager := service.FromContext[pause.Manager](ctx)
	dialer := newContextBlockingDialer()
	bind := NewClientBind(ctx, logger.NOP(), dialer, M.ParseSocksaddr("127.0.0.1:51820"), [3]uint8{})
	tunDevice := &testEndpointDevice{
		done:   make(chan struct{}),
		events: make(chan wgTun.Event),
	}
	wgDevice := device.NewDevice(ctx, tunDevice, bind, &device.Logger{
		Verbosef: func(string, ...any) {},
		Errorf:   t.Logf,
	}, 1)
	endpoint := &Endpoint{
		options:      EndpointOptions{Context: ctx, Logger: logger.NOP()},
		pause:        pauseManager,
		pauseUpdated: make(chan struct{}),
		done:         make(chan struct{}),
		returnDevice: &returnDeviceWrapper{},
	}
	endpoint.clientBind.Store(bind)
	endpoint.device.Store(wgDevice)
	endpoint.pauseCallback = pauseManager.RegisterCallback(endpoint.onPauseUpdated)
	if err := wgDevice.IpcSet("private_key=77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a\n" +
		"public_key=de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f\n" +
		"endpoint=127.0.0.1:51820\n" +
		"allowed_ip=10.0.0.0/24\n" +
		"persistent_keepalive_interval=1\n"); err != nil {
		t.Fatal(err)
	}
	upDone := make(chan error, 1)
	go func() {
		upDone <- endpoint.startDevice()
	}()

	// Wait until Send/receive triggers ListenPacket and blocks on bindCtx.
	select {
	case <-dialer.started:
	case <-time.After(2 * time.Second):
		t.Fatal("ListenPacket did not start")
	}

	// Pause network so ClientBind would previously wait inside Send while holding device.net RLock.
	pauseManager.NetworkPause()

	closeDone := make(chan error, 1)
	go func() {
		closeDone <- endpoint.Close()
	}()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Endpoint.Close deadlocked while ClientBind.Send was active")
	}
	select {
	case <-upDone:
	case <-time.After(3 * time.Second):
		t.Fatal("startDevice did not return after Endpoint.Close")
	}
}

func TestClientBindShutdownPreventsSubsequentOpen(t *testing.T) {
	ctx := context.Background()
	dialer := newContextBlockingDialer()
	bind := NewClientBind(ctx, logger.NOP(), dialer, M.ParseSocksaddr("127.0.0.1:51820"), [3]uint8{})
	if err := bind.Shutdown(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := bind.Open(0); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("expected net.ErrClosed after Shutdown, got %v", err)
	}
	ep, err := bind.ParseEndpoint("127.0.0.1:51820")
	if err != nil {
		t.Fatal(err)
	}
	if err = bind.Send([][]byte{make([]byte, 32)}, ep, 0); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("expected net.ErrClosed from Send after Shutdown, got %v", err)
	}
}

type contextBlockingDialer struct {
	started   chan struct{}
	startOnce sync.Once
}

func newContextBlockingDialer() *contextBlockingDialer {
	return &contextBlockingDialer{
		started: make(chan struct{}),
	}
}

func (d *contextBlockingDialer) DialContext(ctx context.Context, _ string, _ M.Socksaddr) (net.Conn, error) {
	d.startOnce.Do(func() { close(d.started) })
	<-ctx.Done()
	return nil, ctx.Err()
}

func (d *contextBlockingDialer) ListenPacket(ctx context.Context, _ M.Socksaddr) (net.PacketConn, error) {
	d.startOnce.Do(func() { close(d.started) })
	<-ctx.Done()
	return nil, ctx.Err()
}

type failingDialer struct{}

func (failingDialer) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, errors.New("dial failed")
}

func (failingDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("listen failed")
}

type blockingDialer struct {
	started     chan struct{}
	release     chan struct{}
	startOnce   sync.Once
	releaseOnce sync.Once
	conn        net.PacketConn
}

type trackingPacketConn struct {
	closed atomic.Bool
}

func (*trackingPacketConn) ReadFrom([]byte) (int, net.Addr, error)    { return 0, nil, net.ErrClosed }
func (*trackingPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) { return len(p), nil }
func (c *trackingPacketConn) Close() error {
	c.closed.Store(true)
	return nil
}
func (*trackingPacketConn) LocalAddr() net.Addr              { return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)} }
func (*trackingPacketConn) SetDeadline(time.Time) error      { return nil }
func (*trackingPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (*trackingPacketConn) SetWriteDeadline(time.Time) error { return nil }

type endpointPauseManager struct {
	access      sync.Mutex
	paused      bool
	callback    pause.Callback
	waiting     chan struct{}
	waitingOnce sync.Once
}

func newEndpointPauseManager() *endpointPauseManager {
	return &endpointPauseManager{
		paused:  true,
		waiting: make(chan struct{}),
	}
}

func (m *endpointPauseManager) DevicePause() {}

func (m *endpointPauseManager) DeviceWake() {}

func (m *endpointPauseManager) NetworkPause() {}

func (m *endpointPauseManager) NetworkWake() {}

func (m *endpointPauseManager) IsDevicePaused() bool {
	return false
}

func (m *endpointPauseManager) IsNetworkPaused() bool {
	return m.IsPaused()
}

func (m *endpointPauseManager) IsPaused() bool {
	m.access.Lock()
	defer m.access.Unlock()
	if m.paused {
		m.waitingOnce.Do(func() { close(m.waiting) })
	}
	return m.paused
}

func (m *endpointPauseManager) WaitActive() {}

func (m *endpointPauseManager) WaitActiveContext(context.Context) {}

func (m *endpointPauseManager) RegisterCallback(callback pause.Callback) *list.Element[pause.Callback] {
	m.access.Lock()
	m.callback = callback
	m.access.Unlock()
	return nil
}

func (m *endpointPauseManager) UnregisterCallback(*list.Element[pause.Callback]) {
	m.access.Lock()
	m.callback = nil
	m.access.Unlock()
}

func (m *endpointPauseManager) Resume() {
	m.access.Lock()
	m.paused = false
	callback := m.callback
	m.access.Unlock()
	if callback != nil {
		callback(pause.EventNetworkWake)
	}
}

func newBlockingDialer() *blockingDialer {
	return &blockingDialer{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
}

func (d *blockingDialer) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, errors.New("dial failed")
}

func (d *blockingDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	d.startOnce.Do(func() { close(d.started) })
	<-d.release
	if d.conn != nil {
		return d.conn, nil
	}
	return nil, context.Canceled
}

func (d *blockingDialer) Release() {
	d.releaseOnce.Do(func() { close(d.release) })
}

type testPauseManager struct {
	waiting     chan struct{}
	active      chan struct{}
	waitingOnce sync.Once
	activeOnce  sync.Once
	paused      atomic.Bool
}

func newTestPauseManager() *testPauseManager {
	manager := &testPauseManager{
		waiting: make(chan struct{}),
		active:  make(chan struct{}),
	}
	manager.paused.Store(true)
	return manager
}

func (m *testPauseManager) DevicePause() {}

func (m *testPauseManager) DeviceWake() {}

func (m *testPauseManager) NetworkPause() {}

func (m *testPauseManager) NetworkWake() {}

func (m *testPauseManager) IsDevicePaused() bool {
	return false
}

func (m *testPauseManager) IsNetworkPaused() bool {
	paused := m.paused.Load()
	if paused {
		m.waitingOnce.Do(func() { close(m.waiting) })
	}
	return paused
}

func (m *testPauseManager) IsPaused() bool {
	paused := m.paused.Load()
	if paused {
		m.waitingOnce.Do(func() { close(m.waiting) })
	}
	return paused
}

func (m *testPauseManager) WaitActive() {
	m.waitingOnce.Do(func() { close(m.waiting) })
	<-m.active
}

func (m *testPauseManager) WaitActiveContext(ctx context.Context) {
	m.waitingOnce.Do(func() { close(m.waiting) })
	select {
	case <-m.active:
	case <-ctx.Done():
	}
}

func (m *testPauseManager) RegisterCallback(pause.Callback) *list.Element[pause.Callback] {
	return nil
}

func (m *testPauseManager) UnregisterCallback(*list.Element[pause.Callback]) {}

func (m *testPauseManager) Resume() {
	m.paused.Store(false)
	m.activeOnce.Do(func() { close(m.active) })
}
