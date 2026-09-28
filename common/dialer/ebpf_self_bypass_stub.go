//go:build !with_ebpf || (!linux && !android)

package dialer

import (
	"net"
	"syscall"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/control"
)

func bindEBPFSelfBypassConnLifecycle(_ adapter.NetworkManager, conn net.Conn) net.Conn {
	return conn
}

func bindEBPFSelfBypassPacketConnLifecycle(_ adapter.NetworkManager, conn net.PacketConn) net.PacketConn {
	return conn
}

func EBPFSelfBypassCleanup(adapter.NetworkManager, syscall.RawConn) func() {
	return nil
}

func PrepareEBPFSelfBypass(adapter.NetworkManager, []option.Inbound, *adapter.Scope) error {
	return nil
}

func AppendEBPFSelfBypass(_ adapter.NetworkManager, controlFunc control.Func) control.Func {
	return controlFunc
}

func appendEBPFSelfBypass(_ adapter.NetworkManager, dialerControl, listenerControl control.Func) (control.Func, control.Func) {
	return dialerControl, listenerControl
}
