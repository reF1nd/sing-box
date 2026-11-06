//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"testing"

	commonEBPF "github.com/CHIZI-0618/sing-ebpf"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
)

type rejectingClaimNetworkManager struct {
	adapter.NetworkManager
}

func (rejectingClaimNetworkManager) ClaimEBPFSelfBypass(*commonEBPF.SelfBypass) bool {
	return false
}

// The box closes an unclaimed tracker when it closes before initialization;
// an inbound that loses that race must not start with the closed tracker.
func TestInitializeFailsWhenSelfBypassWasReleased(t *testing.T) {
	tracker, err := commonEBPF.NewSelfBypass()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tracker.Close() })
	inbound := &Inbound{
		logger:           log.NewNOPFactory().NewLogger("ebpf"),
		networkManager:   rejectingClaimNetworkManager{},
		inboundResources: inboundResources{selfBypass: tracker},
	}
	scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
	if err = inbound.Start(adapter.StartStateInitialize, scope); err == nil {
		t.Fatal("initialized with a self-bypass the box already released")
	}
	if err = scope.Close(); err != nil {
		t.Fatal(err)
	}
	if !tracker.IsClosed() {
		t.Fatal("failed initialization did not release the self-bypass")
	}
}
