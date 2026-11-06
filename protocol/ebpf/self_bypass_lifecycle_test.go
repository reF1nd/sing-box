//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"errors"
	"net"
	"syscall"
	"testing"
	"time"

	commonEBPF "github.com/CHIZI-0618/sing-ebpf"
	"github.com/sagernet/sing-box/adapter"
)

type selfBypassOwnerTestNetwork struct {
	adapter.NetworkManager
	tracker *commonEBPF.SelfBypass
}

func (n *selfBypassOwnerTestNetwork) EBPFSelfBypass() *commonEBPF.SelfBypass {
	return n.tracker
}

func (n *selfBypassOwnerTestNetwork) ClearEBPFSelfBypass(tracker *commonEBPF.SelfBypass) {
	if n.tracker == tracker {
		n.tracker = nil
	}
}

// The inbound owns the prepared self-bypass from construction. Dials made
// before Start create its kernel map, so Close must release the map even if
// the inbound never started, for example when startup failed elsewhere.
func TestCloseReleasesSelfBypassWithoutStart(t *testing.T) {
	tracker, err := commonEBPF.NewSelfBypassWithCapacity(commonEBPF.CompactSelfBypassSocketCapacity)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tracker.Close() })
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	rawConn, err := conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tracker.RegisterSocket(rawConn); err != nil {
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.ENOSYS) {
			t.Skipf("kernel BPF map creation unavailable: %v", err)
		}
		t.Fatal(err)
	}
	if tracker.IsClosed() {
		t.Fatal("self-bypass map was not created")
	}
	network := &selfBypassOwnerTestNetwork{tracker: tracker}
	inbound := &Inbound{ctx: context.Background(), networkManager: network, udpTimeout: time.Minute, inboundResources: inboundResources{selfBypass: tracker}}
	inbound.udpNat = newUDPNATService(inbound, inbound.preparePacketConnection, time.Minute)
	if err = inbound.Close(); err != nil {
		t.Fatal(err)
	}
	if !tracker.IsClosed() || network.EBPFSelfBypass() != nil {
		t.Fatal("an inbound closed before start left its self-bypass map open")
	}
}
