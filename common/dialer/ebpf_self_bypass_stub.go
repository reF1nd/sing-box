//go:build !with_ebpf || (!linux && !android)

package dialer

import (
	"context"
	"net"
	"syscall"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/control"
)

func appendEBPFSelfBypassDialer(_ adapter.NetworkManager, _ *net.Dialer) {}

func (d *DefaultDialer) selfBypassTracker() any { return nil }

func (d *DefaultDialer) dialWithSelfBypass(ctx context.Context, dialer net.Dialer, network, address string) (net.Conn, error) {
	return dialer.DialContext(ctx, network, address)
}

func bindEBPFSelfBypassConnLifecycle(_ adapter.NetworkManager, conn net.Conn) net.Conn {
	return conn
}

func bindEBPFSelfBypassPacketConnLifecycle(_ adapter.NetworkManager, conn net.PacketConn) net.PacketConn {
	return conn
}

func RegisterEBPFSelfBypassPacketConn(_ adapter.NetworkManager, _ net.PacketConn) error {
	return nil
}

func EBPFSelfBypassCleanup(adapter.NetworkManager, syscall.RawConn) func() {
	return nil
}

func PrepareEBPFSelfBypass(adapter.NetworkManager, []option.Inbound) error {
	return nil
}

func CloseUnclaimedEBPFSelfBypass(adapter.NetworkManager) error {
	return nil
}

func AppendEBPFSelfBypass(_ adapter.NetworkManager, controlFunc control.Func) control.Func {
	return controlFunc
}

func appendEBPFSelfBypass(_ adapter.NetworkManager, dialerControl, listenerControl control.Func) (control.Func, control.Func) {
	return dialerControl, listenerControl
}
