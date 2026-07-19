package wireguard

import (
	"errors"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

// Use an actual peer with protocol timers. Devices without peers cannot catch
// a Down waiting for a paused timer while the pause manager's lock is held.
func TestEndpointPausedPeerNetworkRecovery(t *testing.T) {
	for _, deviceWakeFirst := range []bool{false, true} {
		name := "network-wake-first"
		if deviceWakeFirst {
			name = "device-wake-first"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				endpoint, manager, bind := newTestEndpoint(t)
				// Public RFC 7748 test keys; no real network endpoint is needed.
				if err := endpoint.device.IpcSet("private_key=77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a\n" +
					"public_key=de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f\n" +
					"persistent_keepalive_interval=1\n"); err != nil {
					t.Fatal(err)
				}
				manager.DevicePause()
				time.Sleep(2 * time.Second)
				synctest.Wait()
				var returned atomic.Bool
				go func() {
					manager.NetworkPause()
					returned.Store(true)
				}()
				synctest.Wait()
				if !returned.Load() {
					t.Fatal("network callback blocked on the peer's paused timers")
				}
				if err := endpoint.startDevice(); !errors.Is(err, errNetworkPaused) {
					t.Fatalf("expected network pause before wake, got %v", err)
				}
				if deviceWakeFirst {
					manager.DeviceWake()
					manager.NetworkWake()
				} else {
					manager.NetworkWake()
					manager.DeviceWake()
				}
				synctest.Wait()
				if err := endpoint.startDevice(); err != nil {
					t.Fatalf("endpoint did not recover: %v", err)
				}
				if got := bind.opens.Load(); got != 2 {
					t.Fatalf("bind was opened %d times, want 2", got)
				}
				manager.DevicePause()
				time.Sleep(2 * time.Second)
				synctest.Wait()
				// Close must also succeed before service context cancellation.
				if err := endpoint.Close(); err != nil {
					t.Fatal(err)
				}
			})
		})
	}
}
