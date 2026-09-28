//go:build with_ebpf && (linux || android)

package dialer

import (
	"context"
	"errors"
	"syscall"
	"testing"

	commonEBPF "github.com/CHIZI-0618/sing-ebpf"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
)

type selfBypassTestNetwork struct {
	adapter.NetworkManager
	tracker *commonEBPF.SelfBypass
}

func (n *selfBypassTestNetwork) SetEBPFSelfBypass(tracker *commonEBPF.SelfBypass) error {
	n.tracker = tracker
	return nil
}

func (n *selfBypassTestNetwork) ClearEBPFSelfBypass(tracker *commonEBPF.SelfBypass) {
	if n.tracker == tracker {
		n.tracker = nil
	}
}

func TestPrepareEBPFSelfBypassRequiresScope(t *testing.T) {
	network := new(selfBypassTestNetwork)
	inbounds := []option.Inbound{{Type: C.TypeEBPF, Options: &option.EBPFInboundOptions{}}}
	if err := PrepareEBPFSelfBypass(network, inbounds, nil); err == nil {
		t.Fatal("accepted a kernel resource without a lifecycle scope")
	}
	if network.tracker != nil {
		t.Fatal("allocated self-bypass before validating scope")
	}
}

func TestPrepareEBPFSelfBypassClosesWithoutInboundStart(t *testing.T) {
	network := new(selfBypassTestNetwork)
	scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
	t.Cleanup(func() { _ = scope.Close() })
	inbounds := []option.Inbound{{Type: C.TypeEBPF, Options: &option.EBPFInboundOptions{}}}
	if err := PrepareEBPFSelfBypass(network, inbounds, scope); err != nil {
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.ENOSYS) {
			t.Skipf("kernel BPF map creation unavailable: %v", err)
		}
		t.Fatal(err)
	}
	tracker := network.tracker
	if tracker == nil || tracker.IsClosed() {
		t.Fatal("self-bypass map was not prepared")
	}
	if err := scope.Close(); err != nil {
		t.Fatal(err)
	}
	if !tracker.IsClosed() || network.tracker != nil {
		t.Fatal("unstarted self-bypass map survived scope cleanup")
	}
}
