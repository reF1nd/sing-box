//go:build with_ebpf && (linux || android)

package dialer

import (
	"context"
	"errors"
	"net"
	"sync"
	"syscall"
	"testing"

	commonEBPF "github.com/CHIZI-0618/sing-ebpf"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	N "github.com/sagernet/sing/common/network"
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
