package wireguard

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"
	"github.com/sagernet/wireguard-go/conn"
	"github.com/sagernet/wireguard-go/device"
	wgTun "github.com/sagernet/wireguard-go/tun"
)

func TestEndpointWakeRestoresBind(t *testing.T) {
	for _, deviceWakeFirst := range []bool{false, true} {
		name := "network-wake-first"
		if deviceWakeFirst {
			name = "device-wake-first"
		}
		t.Run(name, func(t *testing.T) {
			endpoint, pauseManager, bind := newTestEndpoint(t)
			pauseManager.DevicePause()
			pauseManager.NetworkPause()
			firstWake, lastWake := pauseManager.NetworkWake, pauseManager.DeviceWake
			if deviceWakeFirst {
				firstWake, lastWake = lastWake, firstWake
			}
			if err := endpoint.BindUpdate(); err != nil {
				t.Fatal(err)
			}
			if got := bind.opens.Load(); got != 1 {
				t.Fatalf("bind reopened while still paused: opens=%d", got)
			}
			firstWake()
			wantOpens := int32(2)
			if deviceWakeFirst {
				wantOpens = 1
			}
			if got := bind.opens.Load(); got != wantOpens {
				t.Fatalf("unexpected bind state after first wake: opens=%d, want %d", got, wantOpens)
			}
			lastWake()
			if got := bind.opens.Load(); got != 2 {
				t.Fatalf("bind did not reopen on network wake: opens=%d", got)
			}
		})
	}
}

func TestEndpointDeviceSleepAllowsTraffic(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		endpoint, pauseManager, bind := newTestEndpoint(t)
		closes := bind.closes.Load()
		pauseManager.DevicePause()
		if got := bind.closes.Load(); got != closes {
			t.Fatalf("device sleep closed the bind: closes=%d, want %d", got, closes)
		}
		started := time.Now()
		if err := endpoint.ensureDeviceStarted(t.Context()); err != nil {
			t.Fatalf("device sleep blocked connection startup: %v", err)
		}
		packet := make([]byte, 20)
		packet[0] = 0x45
		if err := endpoint.WritePackets([][]byte{packet}); err != nil {
			t.Fatalf("device sleep blocked packet write: %v", err)
		}
		if elapsed := time.Since(started); elapsed != 0 {
			t.Fatalf("traffic waited for device wake: %v", elapsed)
		}
		if got := bind.opens.Load(); got != 1 {
			t.Fatalf("device sleep restarted the bind: opens=%d", got)
		}
		if err := endpoint.BindUpdate(); err != nil {
			t.Fatal(err)
		}
		if got := bind.opens.Load(); got != 2 {
			t.Fatalf("device sleep blocked bind update: opens=%d", got)
		}
		pauseManager.DeviceWake()
		if got := bind.opens.Load(); got != 2 {
			t.Fatalf("device wake restarted the bind: opens=%d", got)
		}
	})
}

func TestEndpointTrafficRetriesFailedNetworkWake(t *testing.T) {
	endpoint, pauseManager, bind := newTestEndpoint(t)
	pauseManager.NetworkPause()
	bind.failNext.Store(true)
	pauseManager.NetworkWake()
	if got := bind.opens.Load(); got != 2 {
		t.Fatalf("network wake did not attempt to reopen bind: opens=%d", got)
	}
	if err := endpoint.WritePackets(nil); err != nil {
		t.Fatal(err)
	}
	if got := bind.opens.Load(); got != 3 {
		t.Fatalf("traffic did not retry failed network wake: opens=%d", got)
	}
}

func TestEndpointBindUpdateWithoutDevice(t *testing.T) {
	endpoint := &Endpoint{}
	if err := endpoint.BindUpdate(); err != nil {
		t.Fatalf("bind update before start: %v", err)
	}
	endpoint, _, _ = newTestEndpoint(t)
	if err := endpoint.Close(); err != nil {
		t.Fatal(err)
	}
	if err := endpoint.BindUpdate(); err != nil {
		t.Fatalf("bind update after close: %v", err)
	}
}

func TestEndpointWritePacketsDoesNotWaitForWake(t *testing.T) {
	for _, testCase := range []struct {
		name  string
		pause func(pause.Manager)
	}{
		{"network", func(manager pause.Manager) { manager.NetworkPause() }},
		{"both", func(manager pause.Manager) {
			manager.DevicePause()
			manager.NetworkPause()
		}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				endpoint, pauseManager, _ := newTestEndpoint(t)
				testCase.pause(pauseManager)
				packet := make([]byte, 20)
				packet[0] = 0x45
				started := time.Now()
				err := endpoint.WritePackets([][]byte{packet})
				if !errors.Is(err, errNetworkPaused) {
					t.Fatalf("expected paused error, got %v", err)
				}
				if elapsed := time.Since(started); elapsed != 0 {
					t.Fatalf("port write waited for network wake: %v", elapsed)
				}
			})
		})
	}
}

func TestEndpointWritePacketsAfterClose(t *testing.T) {
	endpoint, pauseManager, _ := newTestEndpoint(t)
	pauseManager.NetworkPause()
	if err := endpoint.Close(); err != nil {
		t.Fatal(err)
	}
	if err := endpoint.WritePackets(nil); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("expected closed error, got %v", err)
	}
}

func TestEndpointConcurrentPauseAndPacketWrites(t *testing.T) {
	endpoint, pauseManager, _ := newTestEndpoint(t)
	var wg sync.WaitGroup
	wg.Go(func() {
		for range 100 {
			pauseManager.DevicePause()
			pauseManager.NetworkPause()
			pauseManager.NetworkWake()
			pauseManager.DeviceWake()
		}
	})
	wg.Go(func() {
		for range 100 {
			if err := endpoint.WritePackets(nil); err != nil && !errors.Is(err, errNetworkPaused) {
				t.Errorf("write during pause transition: %v", err)
			}
		}
	})
	wg.Wait()
}

func newTestEndpoint(t *testing.T) (*Endpoint, pause.Manager, *testEndpointBind) {
	t.Helper()
	ctx := pause.WithDefaultManager(t.Context())
	pauseManager := service.FromContext[pause.Manager](ctx)
	bind := &testEndpointBind{}
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
	endpoint.device = wgDevice
	endpoint.pauseCallback = pauseManager.RegisterCallback(endpoint.onPauseUpdated)
	t.Cleanup(func() { _ = endpoint.Close() })
	if err := wgDevice.Up(); err != nil {
		t.Fatal(err)
	}
	return endpoint, pauseManager, bind
}

type testEndpointDevice struct {
	wgTun.Device
	done   chan struct{}
	events chan wgTun.Event
	once   sync.Once
}

func (d *testEndpointDevice) MTU() (int, error) { return 1408, nil }

func (d *testEndpointDevice) BatchSize() int { return 1 }

func (d *testEndpointDevice) Events() <-chan wgTun.Event { return d.events }

func (d *testEndpointDevice) Read([][]byte, []int, int) (int, error) {
	<-d.done
	return 0, net.ErrClosed
}

func (d *testEndpointDevice) Close() error {
	d.once.Do(func() {
		close(d.done)
		close(d.events)
	})
	return nil
}

type testEndpointBind struct {
	conn.Bind
	opens    atomic.Int32
	closes   atomic.Int32
	failNext atomic.Bool
}

func (b *testEndpointBind) Open(uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.opens.Add(1)
	if b.failNext.Swap(false) {
		return nil, 0, errors.New("temporary bind failure")
	}
	return nil, 12345, nil
}

func (b *testEndpointBind) Close() error {
	b.closes.Add(1)
	return nil
}

func (b *testEndpointBind) BatchSize() int { return 1 }
