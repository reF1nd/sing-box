//go:build with_ebpf && (linux || android)

package dialer

import (
	"context"
	"net"
	"sync"
	"syscall"
	"testing"

	commonEBPF "github.com/CHIZI-0618/sing-ebpf"
	"github.com/sagernet/sing-box/adapter"
	N "github.com/sagernet/sing/common/network"
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
	var baseCalled, extraCalled bool
	dialer := &net.Dialer{
		ControlContext: func(context.Context, string, string, syscall.RawConn) error {
			baseCalled = true
			return nil
		},
	}
	appendDialerControl(dialer, func(string, string, syscall.RawConn) error {
		extraCalled = true
		return nil
	})
	if err := dialer.ControlContext(context.Background(), "tcp", "127.0.0.1:1", nil); err != nil {
		t.Fatal(err)
	}
	if !baseCalled || !extraCalled {
		t.Fatalf("control hooks were not chained: base=%v extra=%v", baseCalled, extraCalled)
	}
}
