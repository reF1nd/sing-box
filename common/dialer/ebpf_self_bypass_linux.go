//go:build with_ebpf && (linux || android)

package dialer

import (
	"runtime"
	"syscall"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"

	commonEBPF "github.com/CHIZI-0618/sing-ebpf"
)

func PrepareEBPFSelfBypass(networkManager adapter.NetworkManager, inbounds []option.Inbound) error {
	localInstances := 0
	for _, inbound := range inbounds {
		switch inbound.Type {
		case C.TypeEBPF:
			ebpfOptions, loaded := inbound.Options.(*option.EBPFInboundOptions)
			if !loaded {
				return E.New("invalid eBPF inbound options")
			}
			localEnabled, _ := ebpfOptions.EffectiveEnablement()
			if localEnabled {
				localInstances++
			}
		}
	}
	if localInstances > 1 {
		return E.New("only one local or hybrid eBPF inbound is supported")
	}
	if localInstances == 0 {
		return nil
	}
	var tracker *commonEBPF.SelfBypass
	var err error
	if runtime.GOOS == "android" {
		tracker, err = commonEBPF.NewSelfBypassWithCapacity(commonEBPF.CompactSelfBypassSocketCapacity)
	} else {
		tracker, err = commonEBPF.NewSelfBypass()
	}
	if err != nil {
		return err
	}
	setter, loaded := networkManager.(interface {
		SetEBPFSelfBypass(*commonEBPF.SelfBypass) error
	})
	if !loaded {
		_ = tracker.Close()
		return E.New("network manager does not support eBPF self-bypass sockets")
	}
	if err = setter.SetEBPFSelfBypass(tracker); err != nil {
		_ = tracker.Close()
		return err
	}
	return nil
}

// AppendEBPFSelfBypass appends the eBPF self-bypass registration callback to a
// socket control chain. It is also used by integrations that create sockets
// outside DefaultDialer, such as endpoint-specific network stacks.
func AppendEBPFSelfBypass(networkManager adapter.NetworkManager, controlFunc control.Func) control.Func {
	provider, loaded := networkManager.(interface {
		EBPFSelfBypass() *commonEBPF.SelfBypass
	})
	if !loaded {
		return controlFunc
	}
	selfBypassFunc := func(_ string, _ string, rawConn syscall.RawConn) error {
		tracker := provider.EBPFSelfBypass()
		if tracker == nil {
			return nil
		}
		return tracker.RegisterSocket(rawConn)
	}
	return control.Append(controlFunc, selfBypassFunc)
}

func appendEBPFSelfBypass(networkManager adapter.NetworkManager, dialerControl, listenerControl control.Func) (control.Func, control.Func) {
	return AppendEBPFSelfBypass(networkManager, dialerControl), AppendEBPFSelfBypass(networkManager, listenerControl)
}
