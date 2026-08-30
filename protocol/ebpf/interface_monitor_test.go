//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"errors"
	"net"
	"slices"
	"testing"

	"github.com/sagernet/netlink"
	"github.com/sagernet/sing-box/adapter"
	commonEBPF "github.com/sagernet/sing-box/common/ebpf"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/common/x/list"

	"golang.org/x/sys/unix"
)

func TestDesiredTCAttachmentState(t *testing.T) {
	links := map[string]int{"wlan2": 12, "rndis0": 27}
	interfaces, err := desiredTCAttachmentState(
		"wlan2",
		[]string{"wlan2", "missing0", "rndis0"},
		func(name string) (netlink.Link, error) {
			index, loaded := links[name]
			if !loaded {
				return nil, unix.ENODEV
			}
			return testEthernetLink(name, index), nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(interfaces) != 2 ||
		interfaces["wlan2"].role != (tcInterfaceRole{local: true, shared: true}) ||
		interfaces["rndis0"].role != (tcInterfaceRole{shared: true}) {
		t.Fatalf("unexpected desired interfaces: %+v", interfaces)
	}
	if interfaces["wlan2"].framing != commonEBPF.TCLinkFramingEthernet {
		t.Fatalf("unexpected wlan2 framing: %v", interfaces["wlan2"].framing)
	}

	expectedErr := errors.New("lookup failed")
	_, err = desiredTCAttachmentState("", []string{"wlan2"}, func(string) (netlink.Link, error) {
		return nil, expectedErr
	})
	if !errors.Is(err, expectedErr) {
		t.Fatalf("unexpected lookup error: %v", err)
	}
}

func TestTCAttachmentTopologyChanged(t *testing.T) {
	attachment := func(name string, index int, role tcInterfaceRole) *tcInterfaceAttachment {
		return &tcInterfaceAttachment{
			interfaceName:  name,
			interfaceIndex: index,
			framing:        commonEBPF.TCLinkFramingEthernet,
			role:           role,
		}
	}
	state := func(index int, role tcInterfaceRole) tcAttachmentState {
		return tcAttachmentState{index: index, framing: commonEBPF.TCLinkFramingEthernet, role: role}
	}
	testCases := []struct {
		name        string
		attachments []*tcInterfaceAttachment
		desired     map[string]tcAttachmentState
		changed     bool
	}{
		{"empty", nil, map[string]tcAttachmentState{}, false},
		{"appeared", nil, map[string]tcAttachmentState{"wlan2": state(12, tcInterfaceRole{shared: true})}, true},
		{
			"unchanged",
			[]*tcInterfaceAttachment{attachment("wlan2", 12, tcInterfaceRole{shared: true})},
			map[string]tcAttachmentState{"wlan2": state(12, tcInterfaceRole{shared: true})},
			false,
		},
		{
			"deleted",
			[]*tcInterfaceAttachment{attachment("wlan2", 12, tcInterfaceRole{shared: true})},
			map[string]tcAttachmentState{},
			true,
		},
		{
			"recreated",
			[]*tcInterfaceAttachment{attachment("wlan2", 12, tcInterfaceRole{shared: true})},
			map[string]tcAttachmentState{"wlan2": state(31, tcInterfaceRole{shared: true})},
			true,
		},
		{
			"role changed",
			[]*tcInterfaceAttachment{attachment("wlan0", 8, tcInterfaceRole{local: true, shared: true})},
			map[string]tcAttachmentState{"wlan0": state(8, tcInterfaceRole{local: true})},
			true,
		},
		{
			"framing changed",
			[]*tcInterfaceAttachment{attachment("rmnet_data2", 21, tcInterfaceRole{local: true})},
			map[string]tcAttachmentState{"rmnet_data2": {
				index:   21,
				framing: commonEBPF.TCLinkFramingRawIP,
				role:    tcInterfaceRole{local: true},
			}},
			true,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			if changed := tcAttachmentTopologyChanged(testCase.attachments, testCase.desired); changed != testCase.changed {
				t.Fatalf("unexpected topology result: %v", changed)
			}
		})
	}
}

func TestActiveSharedInterfaces(t *testing.T) {
	configured := []string{"wlan0", "rndis0"}
	if active := activeSharedInterfaces(configured, "wlan0"); !slices.Equal(active, []string{"rndis0"}) {
		t.Fatalf("default upstream was not excluded: %v", active)
	}
	if active := activeSharedInterfaces(configured, "rmnet_data2"); !slices.Equal(active, configured) {
		t.Fatalf("downstream interfaces changed unexpectedly: %v", active)
	}
	if !slices.Equal(configured, []string{"wlan0", "rndis0"}) {
		t.Fatalf("configured interfaces were modified: %v", configured)
	}
}

func TestTCInterfaceMonitorLifecycle(t *testing.T) {
	networkMonitor := &testNetworkUpdateMonitor{}
	defaultMonitor := &testDefaultInterfaceMonitor{current: &control.Interface{Name: "wlan0", Index: 8}}
	inbound := &Inbound{
		ctx: context.Background(),
		networkManager: &testInterfaceNetworkManager{
			networkMonitor: networkMonitor,
			defaultMonitor: defaultMonitor,
			finder:         control.NewDefaultInterfaceFinder(),
		},
	}
	if err := inbound.startTCInterfaceMonitor(); err != nil {
		t.Fatal(err)
	}
	if networkMonitor.callbackCount() != 1 || defaultMonitor.callbackCount() != 1 {
		t.Fatalf("unexpected callback counts after start: network=%d default=%d", networkMonitor.callbackCount(), defaultMonitor.callbackCount())
	}
	if current := inbound.monitoredDefaultInterfaceName(); current != "wlan0" {
		t.Fatalf("unexpected initial default interface: %q", current)
	}
	defaultMonitor.emit(nil)
	if current := inbound.monitoredDefaultInterfaceName(); current != "" {
		t.Fatalf("default interface was not cleared: %q", current)
	}
	defaultMonitor.emit(&control.Interface{Name: "rmnet_data1", Index: 19})
	defaultMonitor.emit(&control.Interface{Name: "rmnet_data2", Index: 21})
	if current := inbound.monitoredDefaultInterfaceName(); current != "rmnet_data2" {
		t.Fatalf("SIM interface switch was not recorded: %q", current)
	}
	if err := inbound.stopTCInterfaceMonitor(); err != nil {
		t.Fatal(err)
	}
	if networkMonitor.callbackCount() != 0 || defaultMonitor.callbackCount() != 0 {
		t.Fatalf("unexpected callback counts after stop: network=%d default=%d", networkMonitor.callbackCount(), defaultMonitor.callbackCount())
	}
}

func TestTCInterfaceNotificationsCoalesce(t *testing.T) {
	networkMonitor := &testNetworkUpdateMonitor{}
	updates := make(chan struct{}, 1)
	inbound := &Inbound{interfaceMonitor: tcInterfaceMonitor{network: networkMonitor, updates: updates}}
	inbound.notifyTCInterfaceUpdate()
	inbound.notifyTCInterfaceUpdate()
	if len(updates) != 1 {
		t.Fatalf("unexpected pending update count: %d", len(updates))
	}
}

func testEthernetLink(name string, index int) netlink.Link {
	return &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{
		Name:         name,
		Index:        index,
		EncapType:    "ether",
		HardwareAddr: net.HardwareAddr{0, 1, 2, 3, 4, 5},
	}}
}

type testInterfaceNetworkManager struct {
	adapter.NetworkManager
	networkMonitor tun.NetworkUpdateMonitor
	defaultMonitor tun.DefaultInterfaceMonitor
	finder         control.InterfaceFinder
}

func (m *testInterfaceNetworkManager) NetworkMonitor() tun.NetworkUpdateMonitor {
	return m.networkMonitor
}

func (m *testInterfaceNetworkManager) InterfaceMonitor() tun.DefaultInterfaceMonitor {
	return m.defaultMonitor
}

func (m *testInterfaceNetworkManager) UpdateInterfaces() error { return nil }

func (m *testInterfaceNetworkManager) InterfaceFinder() control.InterfaceFinder {
	return m.finder
}

type testNetworkUpdateMonitor struct {
	callbacks list.List[tun.NetworkUpdateCallback]
}

func (m *testNetworkUpdateMonitor) Start() error { return nil }

func (m *testNetworkUpdateMonitor) Close() error { return nil }

func (m *testNetworkUpdateMonitor) RegisterCallback(callback tun.NetworkUpdateCallback) *list.Element[tun.NetworkUpdateCallback] {
	return m.callbacks.PushBack(callback)
}

func (m *testNetworkUpdateMonitor) UnregisterCallback(element *list.Element[tun.NetworkUpdateCallback]) {
	m.callbacks.Remove(element)
}

func (m *testNetworkUpdateMonitor) callbackCount() int {
	return len(m.callbacks.Array())
}

type testDefaultInterfaceMonitor struct {
	current   *control.Interface
	callbacks list.List[tun.DefaultInterfaceUpdateCallback]
}

func (m *testDefaultInterfaceMonitor) Start() error { return nil }

func (m *testDefaultInterfaceMonitor) Close() error { return nil }

func (m *testDefaultInterfaceMonitor) DefaultInterface() *control.Interface { return m.current }

func (m *testDefaultInterfaceMonitor) OverrideAndroidVPN() bool { return false }

func (m *testDefaultInterfaceMonitor) AndroidVPNEnabled() bool { return false }

func (m *testDefaultInterfaceMonitor) RegisterCallback(callback tun.DefaultInterfaceUpdateCallback) *list.Element[tun.DefaultInterfaceUpdateCallback] {
	return m.callbacks.PushBack(callback)
}

func (m *testDefaultInterfaceMonitor) UnregisterCallback(element *list.Element[tun.DefaultInterfaceUpdateCallback]) {
	m.callbacks.Remove(element)
}

func (m *testDefaultInterfaceMonitor) RegisterMyInterface(string) {}

func (m *testDefaultInterfaceMonitor) MyInterfaces() []string { return nil }

func (m *testDefaultInterfaceMonitor) callbackCount() int {
	return len(m.callbacks.Array())
}

func (m *testDefaultInterfaceMonitor) emit(networkInterface *control.Interface) {
	m.current = networkInterface
	for _, callback := range m.callbacks.Array() {
		callback(networkInterface, 0)
	}
}
