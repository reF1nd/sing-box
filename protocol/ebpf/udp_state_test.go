//go:build with_ebpf && (linux || android)

package ebpf

import (
	"bytes"
	"net"
	"net/netip"
	"testing"

	commonEBPF "github.com/sagernet/sing-box/common/ebpf"
)

func TestUDPDirectBinding(t *testing.T) {
	var table udpClientTable
	client := netip.MustParseAddrPort("192.0.2.10:53000")
	destination := netip.MustParseAddrPort("1.1.1.1:53")
	sourceMAC := net.HardwareAddr{0x02, 0, 0, 0, 0, 1}
	table.setDirectBinding(client, destination, sourceMAC, 42)
	state, loaded := table.load(client)
	if !loaded {
		t.Fatal("client state was not created")
	}
	if _, loaded := state.redirectBinding(destination); !loaded {
		t.Fatal("direct binding was not installed")
	}
	if actual := state.sourceMACAddress(); !bytes.Equal(actual, sourceMAC) {
		t.Fatalf("unexpected source MAC: %s", actual)
	}
	if state.processSocketCookie() != 42 {
		t.Fatalf("unexpected process socket cookie: %d", state.processSocketCookie())
	}
}

func TestUDPCgroupBindingLifecycle(t *testing.T) {
	var table udpClientTable
	client := netip.MustParseAddrPort("192.0.2.10:53000")
	destination := netip.MustParseAddrPort("1.1.1.1:53")
	redirect := netip.MustParseAddr("127.128.0.7")
	table.setCgroupBinding(client, commonEBPF.OriginalDestination{
		Destination:  destination,
		ConnectedUDP: true,
		SocketCookie: 42,
	}, redirect)
	state, loaded := table.load(client)
	if !loaded || !state.isCgroupDataPlane() {
		t.Fatal("cgroup client state was not created")
	}
	binding, loaded := state.redirectBinding(destination)
	if !loaded || binding.redirectAddress != redirect || !binding.connected {
		t.Fatalf("unexpected cgroup binding: %+v", binding)
	}
	released := table.delete(client, state)
	if len(released) != 1 || released[0] != redirect {
		t.Fatalf("unexpected released redirects: %v", released)
	}
}

func TestUDPReplySocketLifecycle(t *testing.T) {
	var pool udpReplySocketPool
	destination := netip.MustParseAddrPort("1.1.1.1:53")
	created := 0
	create := func(netip.AddrPort) (*net.UDPConn, error) {
		created++
		return net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	}
	first, err := pool.get(destination, create)
	if err != nil {
		t.Fatal(err)
	}
	second, err := pool.get(destination, create)
	if err != nil {
		t.Fatal(err)
	}
	if first != second || created != 1 {
		t.Fatalf("reply socket was not reused: first=%p second=%p created=%d", first, second, created)
	}
	if err = pool.close(); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.get(destination, create); err == nil {
		t.Fatal("closed inbound accepted a reply socket")
	}
	if _, err = first.WriteToUDPAddrPort([]byte{1}, netip.MustParseAddrPort("127.0.0.1:9")); err == nil {
		t.Fatal("UDP reply socket remained open after inbound closure")
	}
}

func TestUDPReplySocketPoolSharesAcrossClients(t *testing.T) {
	var pool udpReplySocketPool
	destination := netip.MustParseAddrPort("1.1.1.1:53")
	created := 0
	create := func(netip.AddrPort) (*net.UDPConn, error) {
		created++
		return net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	}
	first, err := pool.get(destination, create)
	if err != nil {
		t.Fatal(err)
	}
	second, err := pool.get(destination, create)
	if err != nil {
		t.Fatal(err)
	}
	if first != second || created != 1 {
		t.Fatalf("reply socket was not shared: first=%p second=%p created=%d", first, second, created)
	}
	_ = pool.close()
}

func TestUDPReplySocketPoolResetsForNetworkChange(t *testing.T) {
	var pool udpReplySocketPool
	destination := netip.MustParseAddrPort("1.1.1.1:53")
	created := 0
	create := func(netip.AddrPort) (*net.UDPConn, error) {
		created++
		return net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	}
	first, err := pool.get(destination, create)
	if err != nil {
		t.Fatal(err)
	}
	if err = pool.reset(); err != nil {
		t.Fatal(err)
	}
	second, err := pool.get(destination, create)
	if err != nil {
		t.Fatal(err)
	}
	if first == second || created != 2 {
		t.Fatalf("network reset did not replace the reply socket: first=%p second=%p created=%d", first, second, created)
	}
	if _, err = first.WriteToUDPAddrPort([]byte{1}, netip.MustParseAddrPort("127.0.0.1:9")); err == nil {
		t.Fatal("reset reply socket remained open")
	}
	_ = pool.close()
}

func TestUDPDirectReplyBindingChecksGeneration(t *testing.T) {
	var table udpClientTable
	client := netip.MustParseAddrPort("192.0.2.10:53000")
	base := netip.MustParseAddrPort("1.1.1.1:53")
	reply := netip.MustParseAddrPort("8.8.8.8:53")
	table.setDirectBinding(client, base, nil, 0)
	state, _ := table.load(client)
	if !table.setDirectReplyBinding(client, state, reply) {
		t.Fatal("reply binding was not installed")
	}
	if binding, loaded := state.redirectBinding(reply); !loaded || !binding.replyAlias {
		t.Fatalf("unexpected reply binding: %+v", binding)
	}
	table.delete(client, state)
	if table.setDirectReplyBinding(client, state, netip.MustParseAddrPort("9.9.9.9:53")) {
		t.Fatal("closed session was resurrected")
	}
}
