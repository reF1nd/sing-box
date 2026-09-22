//go:build !with_ebpf || (!linux && !android)

package dialer

import (
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/control"
)

func PrepareEBPFSelfBypass(adapter.NetworkManager, []option.Inbound) error {
	return nil
}

func AppendEBPFSelfBypass(_ adapter.NetworkManager, controlFunc control.Func) control.Func {
	return controlFunc
}

func appendEBPFSelfBypass(_ adapter.NetworkManager, dialerControl, listenerControl control.Func) (control.Func, control.Func) {
	return dialerControl, listenerControl
}
