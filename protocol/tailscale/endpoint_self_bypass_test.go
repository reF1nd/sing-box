//go:build with_gvisor

package tailscale

import (
	"net"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/sagernet/tailscale/types/nettype"
)

type selfBypassTestPacketConn struct {
	nettype.PacketConn
	cleanupCount *atomic.Int32
	closedEarly  atomic.Bool
}

func (c *selfBypassTestPacketConn) Close() error {
	if c.cleanupCount.Load() != 1 {
		c.closedEarly.Store(true)
	}
	return net.ErrClosed
}

func TestSelfBypassPacketConnCleanupBeforeClose(t *testing.T) {
	var cleanupCount atomic.Int32
	underlying := &selfBypassTestPacketConn{cleanupCount: &cleanupCount}
	conn := &selfBypassPacketConn{PacketConn: underlying, cleanup: func() { cleanupCount.Add(1) }}
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			if err := conn.Close(); err != net.ErrClosed {
				t.Errorf("close error not preserved: %v", err)
			}
		})
	}
	workers.Wait()
	if cleanupCount.Load() != 1 || underlying.closedEarly.Load() {
		t.Fatal("socket cleanup must run exactly once before closing the underlying socket")
	}
}
