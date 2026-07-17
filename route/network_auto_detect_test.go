//go:build linux || darwin || windows

package route

import (
	"errors"
	"syscall"
	"testing"

	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/common/x/list"
	"github.com/stretchr/testify/require"
)

func TestAutoDetectInterfaceWithAutoRedirectMark(t *testing.T) {
	defaultInterface := &control.Interface{
		Index: 1,
		Name:  "test-wan",
	}
	interfaceFinder := control.NewDefaultInterfaceFinder()
	interfaceFinder.UpdateInterfaces([]control.Interface{*defaultInterface})
	networkManager := &NetworkManager{
		interfaceFinder:        interfaceFinder,
		interfaceMonitor:       &testDefaultInterfaceMonitor{defaultInterface: defaultInterface},
		autoRedirectOutputMark: 0x2024,
	}
	rawConn := new(testRawConn)

	err := networkManager.AutoDetectInterfaceFunc()("udp6", "[2001:db8::1]:443", rawConn)
	require.Error(t, err)
	require.True(t, rawConn.controlled, "auto-detect binding must not be skipped when auto-redirect installs an output mark")
}

type testRawConn struct {
	controlled bool
}

func (c *testRawConn) Control(block func(fd uintptr)) error {
	c.controlled = true
	block(^uintptr(0))
	return nil
}

func (*testRawConn) Read(func(fd uintptr) (done bool)) error {
	return errors.New("unexpected Read call")
}

func (*testRawConn) Write(func(fd uintptr) (done bool)) error {
	return errors.New("unexpected Write call")
}

type testDefaultInterfaceMonitor struct {
	defaultInterface *control.Interface
}

func (*testDefaultInterfaceMonitor) Start() error { return nil }

func (*testDefaultInterfaceMonitor) Close() error { return nil }

func (m *testDefaultInterfaceMonitor) DefaultInterface() *control.Interface {
	return m.defaultInterface
}

func (*testDefaultInterfaceMonitor) OverrideAndroidVPN() bool { return false }

func (*testDefaultInterfaceMonitor) AndroidVPNEnabled() bool { return false }

func (*testDefaultInterfaceMonitor) RegisterCallback(tun.DefaultInterfaceUpdateCallback) *list.Element[tun.DefaultInterfaceUpdateCallback] {
	return nil
}

func (*testDefaultInterfaceMonitor) UnregisterCallback(*list.Element[tun.DefaultInterfaceUpdateCallback]) {
}

func (*testDefaultInterfaceMonitor) RegisterMyInterface(string) {}

func (*testDefaultInterfaceMonitor) MyInterfaces() []string { return nil }

var _ syscall.RawConn = (*testRawConn)(nil)
var _ tun.DefaultInterfaceMonitor = (*testDefaultInterfaceMonitor)(nil)
