//go:build with_ebpf && (linux || android)

package ebpf

import (
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
)

// TestSharedRewriteDiagnosticsDoesNotRaceWithClose exercises the Clash API
// diagnostics read concurrently with data-plane teardown under go test -race.
func TestSharedRewriteDiagnosticsDoesNotRaceWithClose(t *testing.T) {
	inbound := &Inbound{udpTimeout: time.Minute}
	shared := newSharedRewrite(inbound, option.EBPFSharedOptions{})
	inbound.setSharedRewrite(shared)
	shared.setDataPlane(newSharedKernelRuntime(shared.kernelRuntimeHooks(), 1))

	done := make(chan struct{})
	go func() {
		defer close(done)
		for round := 0; round < 2000; round++ {
			inbound.Diagnostics()
		}
	}()
	if err := shared.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	<-done
}
