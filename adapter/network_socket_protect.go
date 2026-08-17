//go:build with_ebpf && (linux || android)

package adapter

import "github.com/sagernet/sing/common/control"

func SocketProtectFunc(networkManager NetworkManager) control.Func {
	protectManager, loaded := networkManager.(SocketProtectManager)
	if !loaded {
		return nil
	}
	return protectManager.SocketProtectFunc()
}
