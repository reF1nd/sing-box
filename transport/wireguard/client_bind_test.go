package wireguard

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service/pause"
	"github.com/sagernet/wireguard-go/conn"
)

func TestClientBindCloseUnblocksPausedReceive(t *testing.T) {
	pauseManager := newTestPauseManager()
	bind := NewClientBind(context.Background(), logger.NOP(), failingDialer{}, true, netip.MustParseAddrPort("127.0.0.1:1"), [3]uint8{})
	bind.pauseManager = pauseManager
	_, _, err := bind.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer pauseManager.Resume()

	receiveDone := make(chan struct{})
	go func() {
		_, _ = bind.receive([][]byte{make([]byte, 2048)}, make([]int, 1), make([]conn.Endpoint, 1))
		close(receiveDone)
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
	case <-receiveDone:
	case <-time.After(time.Second):
		t.Fatal("receive did not exit after bind close")
	}
}

func TestClientBindCloseDoesNotWaitForDial(t *testing.T) {
	dialer := newBlockingDialer()
	bind := NewClientBind(context.Background(), logger.NOP(), dialer, true, netip.MustParseAddrPort("127.0.0.1:1"), [3]uint8{})
	_, _, err := bind.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer dialer.Release()

	receiveDone := make(chan struct{})
	go func() {
		_, _ = bind.receive([][]byte{make([]byte, 2048)}, make([]int, 1), make([]conn.Endpoint, 1))
		close(receiveDone)
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
	case <-receiveDone:
	case <-time.After(time.Second):
		t.Fatal("receive did not exit after dial returned")
	}
}

func TestClientBindNetworkWakeSkipsRetryDelay(t *testing.T) {
	pauseManager := newTestPauseManager()
	bind := NewClientBind(context.Background(), logger.NOP(), failingDialer{}, true, netip.MustParseAddrPort("127.0.0.1:1"), [3]uint8{})
	bind.pauseManager = pauseManager
	waitDone := make(chan bool, 1)
	go func() {
		waitDone <- bind.waitAfterFailure()
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
}

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
	d.startOnce.Do(func() { close(d.started) })
	<-d.release
	return nil, context.Canceled
}

func (d *blockingDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("listen failed")
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
	return m.paused.Load()
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

func (m *testPauseManager) RegisterCallback(pause.Callback) *list.Element[pause.Callback] {
	return nil
}

func (m *testPauseManager) UnregisterCallback(*list.Element[pause.Callback]) {}

func (m *testPauseManager) Resume() {
	m.paused.Store(false)
	m.activeOnce.Do(func() { close(m.active) })
}
