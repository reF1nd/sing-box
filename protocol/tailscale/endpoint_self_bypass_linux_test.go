//go:build with_gvisor && with_ebpf && (linux || android)

package tailscale

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"syscall"
	"testing"

	commonEBPF "github.com/CHIZI-0618/sing-ebpf"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/common/x/list"
)

type testSelfBypassNetworkManager struct {
	adapter.NetworkManager
	tracker          *commonEBPF.SelfBypass
	autoDetectFunc   control.Func
	interfaceFinder  control.InterfaceFinder
	interfaceMonitor tun.DefaultInterfaceMonitor
}

func (m *testSelfBypassNetworkManager) EBPFSelfBypass() *commonEBPF.SelfBypass {
	return m.tracker
}

func (m *testSelfBypassNetworkManager) AutoRedirectOutputMark() uint32 {
	return 0
}

func (m *testSelfBypassNetworkManager) AutoDetectInterfaceFunc() control.Func {
	return m.autoDetectFunc
}

func (m *testSelfBypassNetworkManager) InterfaceFinder() control.InterfaceFinder {
	return m.interfaceFinder
}

func (m *testSelfBypassNetworkManager) InterfaceMonitor() tun.DefaultInterfaceMonitor {
	return m.interfaceMonitor
}

type testStaticInterfaceFinder struct {
	control.InterfaceFinder
	interfaces []control.Interface
	callbacks  list.List[control.InterfaceUpdateCallback]
}

func (f *testStaticInterfaceFinder) Interfaces() []control.Interface {
	return f.interfaces
}

func (f *testStaticInterfaceFinder) RegisterInterfaceUpdateCallback(cb control.InterfaceUpdateCallback) *list.Element[control.InterfaceUpdateCallback] {
	return f.callbacks.PushBack(cb)
}

func (f *testStaticInterfaceFinder) UnregisterInterfaceUpdateCallback(elem *list.Element[control.InterfaceUpdateCallback]) {
	f.callbacks.Remove(elem)
}

type testStaticInterfaceMonitor struct {
	tun.DefaultInterfaceMonitor
	defaultIface *control.Interface
}

func (m *testStaticInterfaceMonitor) DefaultInterface() *control.Interface {
	return m.defaultIface
}

func TestTailscaleListenPacketRegistersEgressPoolMembersForSelfBypass(t *testing.T) {
	// Capacity 2: primary wildcard socket (bound to lo) + 1 UDPEgressPool member fill the map.
	tracker, err := commonEBPF.NewSelfBypassWithCapacity(2)
	if err != nil {
		t.Fatal(err)
	}
	defer tracker.Close()

	// Find loopback (for the primary socket's anchor device bind) and a real up broadcast
	// non-loopback IPv4 interface so UDPEgressPool creates a real member socket on the same port.
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	var loIface, nonDefaultIface *control.Interface
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		if iface.Flags&net.FlagLoopback != 0 {
			loIface = &control.Interface{
				Index: iface.Index,
				Name:  iface.Name,
				Flags: iface.Flags,
			}
			continue
		}
		if iface.Flags&net.FlagPointToPoint != 0 || iface.Flags&net.FlagBroadcast == 0 {
			continue
		}
		addrs, addrErr := iface.Addrs()
		if addrErr != nil {
			continue
		}
		var prefixes []netip.Prefix
		for _, a := range addrs {
			ipNet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip, ok := netip.AddrFromSlice(ipNet.IP)
			if !ok {
				continue
			}
			ip = ip.Unmap()
			if !ip.Is4() || !ip.IsGlobalUnicast() {
				continue
			}
			ones, _ := ipNet.Mask.Size()
			prefixes = append(prefixes, netip.PrefixFrom(ip, ones))
		}
		if len(prefixes) > 0 && nonDefaultIface == nil {
			nonDefaultIface = &control.Interface{
				Index:     iface.Index,
				Name:      iface.Name,
				Flags:     iface.Flags,
				Addresses: prefixes,
			}
		}
	}
	if loIface == nil || nonDefaultIface == nil {
		t.Skip("no suitable loopback + broadcast IPv4 interface pair available for UDPEgressPool member test")
	}

	finder := &testStaticInterfaceFinder{interfaces: []control.Interface{*loIface, *nonDefaultIface}}
	monitor := &testStaticInterfaceMonitor{defaultIface: loIface}

	nm := &testSelfBypassNetworkManager{
		tracker:          tracker,
		autoDetectFunc:   control.BindToInterface(finder, loIface.Name, loIface.Index),
		interfaceFinder:  finder,
		interfaceMonitor: monitor,
	}
	ep := &Endpoint{
		logger:  log.NewNOPFactory().NewLogger("tailscale-test"),
		network: nm,
	}

	conn, err := ep.listenPacket(context.Background(), "udp4", ":0")
	if err != nil {
		if os.Geteuid() != 0 {
			t.Skipf("requires CAP_BPF: %v", err)
		}
		t.Fatal(err)
	}
	defer conn.Close()

	// Ensure listenPacket actually wrapped a UDPEgressConn (meaning at least 1 egress member was created).
	sbConn, ok := conn.(*selfBypassPacketConn)
	if !ok {
		t.Fatalf("expected *selfBypassPacketConn wrapper, got %T", conn)
	}
	if _, isEgress := sbConn.PacketConn.(*tun.UDPEgressConn); !isEgress {
		t.Fatalf("expected *tun.UDPEgressConn inside selfBypassPacketConn, got %T", sbConn.PacketConn)
	}

	// Because both the primary socket and the egress pool member socket are open and
	// registered in the capacity-2 self-bypass map, registering a 3rd live socket must fail.
	extra, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer extra.Close()
	rawExtra, err := extra.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	if reg, regErr := tracker.RegisterSocket(rawExtra); regErr == nil {
		_ = tracker.UnregisterSocket(reg)
		t.Fatal("expected capacity-2 self-bypass map to be full (primary + egress pool member), but 3rd live socket registered")
	} else if !errors.Is(regErr, syscall.E2BIG) {
		t.Fatalf("expected E2BIG on full capacity-2 self-bypass map, got: %v", regErr)
	}
}

func TestAppendEBPFSelfBypassReclaimsClosedSocketAtCapacityOne(t *testing.T) {
	tracker, err := commonEBPF.NewSelfBypassWithCapacity(1)
	if err != nil {
		t.Fatal(err)
	}
	defer tracker.Close()

	nm := &testSelfBypassNetworkManager{tracker: tracker}
	lc := net.ListenConfig{
		Control: dialer.AppendEBPFSelfBypass(nm, nil),
	}
	c1, err := lc.ListenPacket(context.Background(), "udp4", "127.0.0.1:0")
	if err != nil {
		if os.Geteuid() != 0 {
			t.Skipf("requires CAP_BPF: %v", err)
		}
		t.Fatal(err)
	}
	// Close c1 without explicit unregister (simulating external bind/egress member close).
	_ = c1.Close()

	// Second registration on capacity-1 map must succeed via automatic dead-cookie reclaim.
	c2, err := lc.ListenPacket(context.Background(), "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("expected second socket registration to reclaim closed socket slot, got: %v", err)
	}
	defer c2.Close()

	diag := tracker.Diagnostics()
	if diag.ReclaimAttempts == 0 || diag.ReclaimedSockets == 0 {
		t.Fatalf("expected automatic reclaim on capacity-1 map, got diagnostics: %+v", diag)
	}
}
