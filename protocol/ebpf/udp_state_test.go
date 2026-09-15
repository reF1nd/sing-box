//go:build with_ebpf && (linux || android)

package ebpf

import (
	"bytes"
	"net"
	"net/netip"
	"testing"

	commonEBPF "github.com/CHIZI-0618/sing-ebpf"
)

func TestUDPDirectBinding(t *testing.T) {
	var table udpClientTable
	client := netip.MustParseAddrPort("192.0.2.10:53000")
	key := udpSessionKey{Source: client, Scope: udpSessionScopeLocalTC, SocketCookie: 42}
	destination := netip.MustParseAddrPort("1.1.1.1:53")
	sourceMAC := net.HardwareAddr{0x02, 0, 0, 0, 0, 1}
	table.setDirectBinding(key, destination, sourceMAC, 42)
	state, loaded := table.load(key)
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

func TestUDPClientTableSeparatesSocketCookies(t *testing.T) {
	var table udpClientTable
	client := netip.MustParseAddrPort("192.0.2.10:53000")
	destination := netip.MustParseAddrPort("1.1.1.1:53")
	firstKey := udpSessionKey{Source: client, Scope: udpSessionScopeLocalTC, SocketCookie: 1}
	secondKey := udpSessionKey{Source: client, Scope: udpSessionScopeLocalTC, SocketCookie: 2}
	table.setDirectBinding(firstKey, destination, nil, 1)
	table.setDirectBinding(secondKey, destination, nil, 2)
	first, firstLoaded := table.load(firstKey)
	second, secondLoaded := table.load(secondKey)
	if !firstLoaded || !secondLoaded || first == second {
		t.Fatal("same-source sockets did not receive independent client state")
	}
	if first.processSocketCookie() != 1 || second.processSocketCookie() != 2 {
		t.Fatalf("socket cookies crossed sessions: %d %d", first.processSocketCookie(), second.processSocketCookie())
	}
}

func TestUDPCgroupBindingLifecycle(t *testing.T) {
	var table udpClientTable
	client := netip.MustParseAddrPort("192.0.2.10:53000")
	key := udpSessionKey{Source: client, Scope: udpSessionScopeLocalCgroup, SocketCookie: 42}
	destination := netip.MustParseAddrPort("1.1.1.1:53")
	redirect := netip.MustParseAddr("127.128.0.7")
	table.setCgroupBinding(key, commonEBPF.OriginalDestination{
		Destination:  destination,
		ConnectedUDP: true,
		SocketCookie: 42,
	}, redirect)
	state, loaded := table.load(key)
	if !loaded || !state.isCgroupDataPlane() {
		t.Fatal("cgroup client state was not created")
	}
	cachedKey, cached, cachedLoaded := table.cachedCgroupOriginal(client, redirect)
	if !cachedLoaded || cachedKey != key || cached.SocketCookie != 42 {
		t.Fatalf("redirect index returned the wrong cgroup session: key=%+v original=%+v", cachedKey, cached)
	}
	binding, loaded := state.redirectBinding(destination)
	if !loaded || binding.redirectAddress != redirect || !binding.connected {
		t.Fatalf("unexpected cgroup binding: %+v", binding)
	}
	released := table.delete(key, state)
	if len(released) != 1 || released[0] != redirect {
		t.Fatalf("unexpected released redirects: %v", released)
	}
	if _, _, loaded = table.cachedCgroupOriginal(client, redirect); loaded {
		t.Fatal("deleted cgroup session remained in redirect index")
	}
}

func TestSharedUDPClientTableSeparatesIngressInterfaces(t *testing.T) {
	var table sharedUDPClientTable
	client := netip.MustParseAddrPort("192.0.2.10:53000")
	destination := netip.MustParseAddrPort("1.1.1.1:53")
	firstRedirect := netip.MustParseAddr("127.128.0.1")
	secondRedirect := netip.MustParseAddr("127.128.0.2")
	firstKey := udpSessionKey{Source: client, Scope: udpSessionScopeSharedRewrite, InterfaceIndex: 10}
	secondKey := udpSessionKey{Source: client, Scope: udpSessionScopeSharedRewrite, InterfaceIndex: 20}
	table.setBinding(firstKey, destination, firstRedirect, false)
	table.setBinding(secondKey, destination, secondRedirect, false)
	if first, loaded := table.load(firstKey); !loaded || first == nil {
		t.Fatal("first ingress session is missing")
	}
	if second, loaded := table.load(secondKey); !loaded || second == nil {
		t.Fatal("second ingress session is missing")
	}
	key, _, _, loaded := table.cachedPacketState(client, secondRedirect)
	if !loaded || key != secondKey {
		t.Fatalf("redirect index selected the wrong ingress session: %+v", key)
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
	first, release1, err := pool.get(destination, create)
	if err != nil {
		t.Fatal(err)
	}
	release1()
	second, release2, err := pool.get(destination, create)
	if err != nil {
		t.Fatal(err)
	}
	release2()
	if first != second || created != 1 {
		t.Fatalf("reply socket was not reused: first=%p second=%p created=%d", first, second, created)
	}
	if err = pool.close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err = pool.get(destination, create); err == nil {
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
	first, release1, err := pool.get(destination, create)
	if err != nil {
		t.Fatal(err)
	}
	release1()
	second, release2, err := pool.get(destination, create)
	if err != nil {
		t.Fatal(err)
	}
	release2()
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
	first, release1, err := pool.get(destination, create)
	if err != nil {
		t.Fatal(err)
	}
	release1()
	if err = pool.reset(); err != nil {
		t.Fatal(err)
	}
	second, release2, err := pool.get(destination, create)
	if err != nil {
		t.Fatal(err)
	}
	release2()
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
	key := udpSessionKey{Source: client, Scope: udpSessionScopeLocalTC}
	base := netip.MustParseAddrPort("1.1.1.1:53")
	reply := netip.MustParseAddrPort("8.8.8.8:53")
	table.setDirectBinding(key, base, nil, 0)
	state, _ := table.load(key)
	if !table.setDirectReplyBinding(key, state, reply) {
		t.Fatal("reply binding was not installed")
	}
	if binding, loaded := state.redirectBinding(reply); !loaded || !binding.replyAlias {
		t.Fatalf("unexpected reply binding: %+v", binding)
	}
	table.delete(key, state)
	if table.setDirectReplyBinding(key, state, netip.MustParseAddrPort("9.9.9.9:53")) {
		t.Fatal("closed session was resurrected")
	}
}

// TestUDPReplySocketPoolShardsSpreadAcrossDestinationPort proves the reply
// socket pool's shard selection actually uses the destination address, not
// only its port. udpReplySockets.get is keyed by the original destination
// (see the caller in tc_connection.go), and real-world UDP destinations
// overwhelmingly concentrate on a handful of well-known ports (443 for QUIC,
// 53 for DNS, ...) while varying widely in address -- a shard key built from
// the port alone would put every one of those distinct destinations in the
// same shard regardless of how many there are, defeating the 16-way split
// udpReplySocketShardCapacity depends on to bound the pool's total size.
// This generates many distinct destination addresses that all share one
// port and asserts they land across more than one shard.
func TestUDPReplySocketPoolShardsSpreadAcrossDestinationPort(t *testing.T) {
	var pool udpReplySocketPool
	counts := make(map[int]int)
	for i := 0; i < 256; i++ {
		destination := netip.AddrPortFrom(
			netip.AddrFrom4([4]byte{203, 0, byte(i >> 8), byte(i)}),
			443,
		)
		counts[pool.shardIndex(destination)]++
	}
	if len(counts) < 2 {
		t.Fatalf(
			"256 distinct destinations all on port 443 landed in %d shard(s) (%v); "+
				"want them spread across multiple shards -- the shard key must not depend on the port alone",
			len(counts), counts,
		)
	}
}

// TestUDPClientTableShardsSpreadAcrossClientAddress is the client-table
// counterpart: clientShard keys by the LAN client's own address, and two
// different client machines can coincidentally pick the same ephemeral
// source port for unrelated connections (OS ephemeral port ranges overlap
// across independent hosts) -- a shard key that only ever looked at the
// port would then always collide those two clients into the same shard no
// matter how many client addresses are actually in play.
func TestUDPClientTableShardsSpreadAcrossClientAddress(t *testing.T) {
	var table udpClientTable
	counts := make(map[*udpClientShard]int)
	for i := 0; i < 256; i++ {
		client := netip.AddrPortFrom(
			netip.AddrFrom4([4]byte{192, 168, byte(i >> 8), byte(i)}),
			51413,
		)
		counts[table.clientShard(udpSessionKey{Source: client})]++
	}
	if len(counts) < 2 {
		t.Fatalf(
			"256 distinct clients all on the same ephemeral port landed in %d shard(s); "+
				"want them spread across multiple shards -- the shard key must not depend on the port alone",
			len(counts),
		)
	}
}
