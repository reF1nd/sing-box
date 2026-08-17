//go:build !with_ebpf || (!linux && !android)

package adapter

import "github.com/sagernet/sing/common/control"

func SocketProtectFunc(NetworkManager) control.Func {
	return nil
}
