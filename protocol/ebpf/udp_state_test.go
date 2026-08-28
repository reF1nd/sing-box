//go:build with_ebpf && (linux || android)

package ebpf

import (
	"bytes"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"

	ECommon "github.com/sagernet/sing-box/common/ebpf"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

func TestUDPClientTableBindings(t *testing.T) {
	var table udpClientTable
	client := netip.MustParseAddrPort("127.0.0.1:1234")
	destination := netip.MustParseAddrPort("1.1.1.1:443")
	redirectAddress := netip.MustParseAddr("127.128.0.1")

	table.setBinding(client, destination, redirectAddress, false)
	clientState, loaded := table.load(client)
	if !loaded {
		t.Fatal("client state was not created")
	}
	if actual, loaded := clientState.redirectBinding(destination); !loaded || actual.address != redirectAddress {
		t.Fatalf("unexpected redirect binding: %v, %v", actual.address, loaded)
	}
	clientState.setConnected(true, destination)
	if !clientState.isConnected() {
		t.Fatal("connected UDP state was not retained")
	}
	cached, bindingReady, loaded := table.cachedPacketState(client, redirectAddress)
	if !loaded || !bindingReady || cached.original.Destination != destination {
		t.Fatalf("packet state was not cached: %+v, ready=%v, loaded=%v", cached, bindingReady, loaded)
	}
	table.setBinding(client, destination, redirectAddress, false)
}

func TestUDPClientTableCachesPacketInfo(t *testing.T) {
	testCases := []netip.Addr{
		netip.MustParseAddr("127.128.0.9"),
		netip.MustParseAddr("fd53:696e:672d:626f::9"),
	}
	for _, redirectAddress := range testCases {
		t.Run(redirectAddress.String(), func(t *testing.T) {
			var table udpClientTable
			client := netip.MustParseAddrPort("127.0.0.1:9001")
			destination := netip.AddrPortFrom(netip.MustParseAddr("1.1.1.1"), 53)
			table.setBinding(client, destination, redirectAddress, false)
			clientState, _ := table.load(client)
			binding, loaded := clientState.redirectBinding(destination)
			if !loaded || len(binding.packetInfo) == 0 {
				t.Fatal("source packet info was not cached")
			}
			var expectedPacketInfo []byte
			if redirectAddress.Is4() {
				expectedPacketInfo = (&ipv4.ControlMessage{Src: net.IP(redirectAddress.AsSlice())}).Marshal()
			} else {
				expectedPacketInfo = (&ipv6.ControlMessage{Src: net.IP(redirectAddress.AsSlice())}).Marshal()
			}
			if !bytes.Equal(binding.packetInfo, expectedPacketInfo) {
				t.Fatal("cached packet info does not contain the redirect source")
			}
		})
	}
}

func TestUDPClientTableRetainsSharedNetworkSourceMAC(t *testing.T) {
	var table udpClientTable
	client := netip.MustParseAddrPort("192.168.43.10:9001")
	redirectAddress := netip.MustParseAddr("127.128.0.9")
	sourceMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	table.setSharedBinding(client, ECommon.OriginalDestination{
		Destination: netip.MustParseAddrPort("1.1.1.1:53"),
		SourceMAC:   sourceMAC,
	}, redirectAddress, nil)
	clientState, loaded := table.load(client)
	if !loaded {
		t.Fatal("client state was not created")
	}
	if actual := clientState.sourceMACAddress(); !bytes.Equal(actual, sourceMAC) {
		t.Fatalf("unexpected source MAC: %s", actual)
	}
}

func BenchmarkUDPClientTableCacheHit(b *testing.B) {
	var table udpClientTable
	client := netip.MustParseAddrPort("127.0.0.1:9001")
	destination := netip.MustParseAddrPort("1.1.1.1:53")
	redirectAddress := netip.MustParseAddr("127.128.0.9")
	table.setBinding(client, destination, redirectAddress, false)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		cached, bindingReady, loaded := table.cachedPacketState(client, redirectAddress)
		if !loaded || !bindingReady || cached.original.Destination != destination {
			b.Fatal("cached original destination was lost")
		}
	}
}

func BenchmarkUDPClientTableCacheHitParallel(b *testing.B) {
	workerCount := runtime.GOMAXPROCS(0)
	clients := make([]netip.AddrPort, workerCount)
	destinations := make([]netip.AddrPort, workerCount)
	redirectAddresses := make([]netip.Addr, workerCount)
	var table udpClientTable
	for index := range workerCount {
		clients[index] = netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), uint16(9000+index))
		destinations[index] = netip.AddrPortFrom(netip.AddrFrom4([4]byte{1, 1, byte(index >> 8), byte(index)}), 53)
		redirectAddresses[index] = netip.AddrFrom4([4]byte{127, 128, byte(index >> 8), byte(index + 1)})
		table.setBinding(clients[index], destinations[index], redirectAddresses[index], false)
	}
	var nextWorker atomic.Uint32
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		worker := int(nextWorker.Add(1)-1) % workerCount
		for pb.Next() {
			cached, bindingReady, loaded := table.cachedPacketState(clients[worker], redirectAddresses[worker])
			if !loaded || !bindingReady || cached.original.Destination != destinations[worker] {
				b.Fatal("cached original destination was lost")
			}
		}
	})
}

var benchmarkPacketInfo []byte

func BenchmarkUDPSourcePacketInfo(b *testing.B) {
	redirectAddress := netip.MustParseAddr("127.128.0.9")
	b.Run("marshal", func(b *testing.B) {
		for range b.N {
			benchmarkPacketInfo = sourcePacketInfo(redirectAddress)
		}
	})
	b.Run("cached", func(b *testing.B) {
		var table udpClientTable
		client := netip.MustParseAddrPort("127.0.0.1:9001")
		destination := netip.MustParseAddrPort("1.1.1.1:53")
		table.setBinding(client, destination, redirectAddress, false)
		clientState, _ := table.load(client)
		b.ResetTimer()
		for range b.N {
			binding, loaded := clientState.redirectBinding(destination)
			if !loaded {
				b.Fatal("redirect binding was lost")
			}
			benchmarkPacketInfo = binding.packetInfo
		}
	})
}

func TestUDPClientTableDeleteChecksGeneration(t *testing.T) {
	var table udpClientTable
	client := netip.MustParseAddrPort("[::1]:1234")
	oldState := table.loadOrCreate(client)
	if !table.current(client, oldState) {
		t.Fatal("new UDP client state is not current")
	}
	table.delete(client, oldState)
	if table.current(client, oldState) {
		t.Fatal("deleted UDP client state is still current")
	}
	newState := table.loadOrCreate(client)
	table.delete(client, oldState)
	if actual, loaded := table.load(client); !loaded || actual != newState {
		t.Fatal("an old session removed the current UDP client state")
	}
	if table.current(client, oldState) || !table.current(client, newState) {
		t.Fatal("UDP client generation classification is incorrect")
	}
}

func TestUDPClientTableReplyBindingChecksGeneration(t *testing.T) {
	var table udpClientTable
	client := netip.MustParseAddrPort("127.0.0.1:1234")
	destination := netip.MustParseAddrPort("192.0.2.1:5000")
	redirectAddress := netip.MustParseAddr("127.128.0.9")
	state := table.loadOrCreate(client)
	if _, installed := table.setReplyBinding(client, state, destination, redirectAddress); !installed {
		t.Fatal("reply binding was not installed for the current session")
	}
	if binding, loaded := state.redirectBinding(destination); !loaded || binding.address != redirectAddress {
		t.Fatalf("unexpected reply binding: %+v, loaded=%v", binding, loaded)
	}
	table.delete(client, state)
	if _, installed := table.setReplyBinding(client, state, destination, redirectAddress); installed {
		t.Fatal("reply binding resurrected a closed UDP session")
	}
}

func TestUDPClientTableLimitsReplyAliases(t *testing.T) {
	var table udpClientTable
	client := netip.MustParseAddrPort("127.0.0.1:1234")
	state := table.loadOrCreate(client)
	for index := 0; index < udpReplyAliasLimit; index++ {
		destination := netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 0, 2, byte(index + 1)}), 5000)
		redirectAddress := netip.AddrFrom4([4]byte{127, 128, 0, byte(index + 1)})
		if _, installed := table.setReplyBinding(client, state, destination, redirectAddress); !installed {
			t.Fatalf("reply alias %d was not installed", index)
		}
	}
	if _, available := state.replyTemplate(netip.MustParseAddrPort("192.0.2.100:5000"), false); available {
		t.Fatal("reply alias limit was not enforced before reservation")
	}
	if _, installed := table.setReplyBinding(
		client,
		state,
		netip.MustParseAddrPort("192.0.2.100:5000"),
		netip.MustParseAddr("127.128.1.1"),
	); installed {
		t.Fatal("reply alias limit was not enforced during installation")
	}
}

func TestUDPClientTableConcurrentBindings(t *testing.T) {
	var table udpClientTable
	client := netip.MustParseAddrPort("127.0.0.1:4321")
	redirectAddress := netip.MustParseAddr("127.128.0.2")
	const destinationCount = 64
	var waitGroup sync.WaitGroup
	for index := 0; index < destinationCount; index++ {
		waitGroup.Add(1)
		go func(index int) {
			defer waitGroup.Done()
			destination := netip.AddrPortFrom(netip.AddrFrom4([4]byte{1, 0, 0, byte(index + 1)}), 443)
			table.setBinding(client, destination, redirectAddress, false)
		}(index)
	}
	waitGroup.Wait()
	clientState, loaded := table.load(client)
	if !loaded {
		t.Fatal("client state was not created")
	}
	clientState.access.RLock()
	bindingCount := len(clientState.bindings)
	clientState.access.RUnlock()
	if bindingCount != destinationCount {
		t.Fatalf("unexpected binding count: got %d, want %d", bindingCount, destinationCount)
	}
}

func TestUDPClientTableSharesUnconnectedRedirect(t *testing.T) {
	var table udpClientTable
	destination := netip.MustParseAddrPort("1.1.1.1:443")
	redirectAddress := netip.MustParseAddr("127.128.0.3")
	client1 := netip.MustParseAddrPort("127.0.0.1:1001")
	client2 := netip.MustParseAddrPort("127.0.0.1:1002")

	table.setBinding(client1, destination, redirectAddress, false)
	table.setBinding(client2, destination, redirectAddress, false)
	if references := redirectReferenceCount(&table, redirectAddress); references != 2 {
		t.Fatalf("unexpected shared redirect references: %d", references)
	}
	state1, _ := table.load(client1)
	if released := table.delete(client1, state1); len(released) != 0 {
		t.Fatalf("redirect released while another client still referenced it: %v", released)
	}
	state2, _ := table.load(client2)
	released := table.delete(client2, state2)
	if len(released) != 1 || released[0] != redirectAddress {
		t.Fatalf("redirect was not released with the last client: %v", released)
	}
}

func TestUDPClientTableSeparatesSharedRedirectsByClient(t *testing.T) {
	var table udpClientTable
	destination := netip.MustParseAddrPort("1.1.1.1:443")
	redirectAddress := netip.MustParseAddr("127.128.0.3")
	client1 := netip.MustParseAddrPort("192.168.43.10:1001")
	client2 := netip.MustParseAddrPort("192.168.43.11:1001")

	table.setSharedBinding(client1, ECommon.OriginalDestination{Destination: destination}, redirectAddress, nil)
	table.setSharedBinding(client2, ECommon.OriginalDestination{Destination: destination}, redirectAddress, nil)
	state1, _ := table.load(client1)
	if released := table.deleteShared(client1, state1); len(released) != 1 {
		t.Fatalf("first client flow was not released independently: %v", released)
	}
	state2, _ := table.load(client2)
	if released := table.deleteShared(client2, state2); len(released) != 1 {
		t.Fatalf("second client flow was not released independently: %v", released)
	}
}

func TestUDPClientTableDoesNotReferenceConnectedRedirect(t *testing.T) {
	var table udpClientTable
	client := netip.MustParseAddrPort("127.0.0.1:2001")
	destination := netip.MustParseAddrPort("8.8.8.8:53")
	redirectAddress := netip.MustParseAddr("127.128.0.4")

	table.setBinding(client, destination, redirectAddress, true)
	if references := redirectReferenceCount(&table, redirectAddress); references != 0 {
		t.Fatalf("connected redirect entered userspace reference table: %d", references)
	}
	state, _ := table.load(client)
	if released := table.delete(client, state); len(released) != 0 {
		t.Fatalf("connected redirect was selected for userspace deletion: %v", released)
	}
}

func TestUDPClientTableReplacesRedirectReference(t *testing.T) {
	var table udpClientTable
	client := netip.MustParseAddrPort("127.0.0.1:3001")
	destination := netip.MustParseAddrPort("9.9.9.9:53")
	oldRedirect := netip.MustParseAddr("127.128.0.5")
	newRedirect := netip.MustParseAddr("127.128.0.6")

	table.setBinding(client, destination, oldRedirect, false)
	released := table.setBinding(client, destination, newRedirect, false)
	if len(released) != 1 || released[0] != oldRedirect {
		t.Fatalf("old redirect was not released: %v", released)
	}
	if references := redirectReferenceCount(&table, oldRedirect); references != 0 {
		t.Fatalf("old redirect still has references: %d", references)
	}
	if references := redirectReferenceCount(&table, newRedirect); references != 1 {
		t.Fatalf("new redirect has unexpected references: %d", references)
	}
	if _, loaded := table.cachedOriginal(client, oldRedirect); loaded {
		t.Fatal("old redirect original destination remained cached")
	}
}

func TestUDPClientTableRetainsSharedRedirectOriginal(t *testing.T) {
	var table udpClientTable
	client := netip.MustParseAddrPort("127.0.0.1:3002")
	firstDestination := netip.MustParseAddrPort("9.9.9.9:53")
	secondDestination := netip.MustParseAddrPort("149.112.112.112:53")
	oldRedirect := netip.MustParseAddr("127.128.0.5")
	newRedirect := netip.MustParseAddr("127.128.0.6")

	table.setBinding(client, firstDestination, oldRedirect, false)
	table.setBinding(client, secondDestination, oldRedirect, false)
	table.setBinding(client, firstDestination, newRedirect, false)
	if _, loaded := table.cachedOriginal(client, oldRedirect); !loaded {
		t.Fatal("referenced redirect original destination was removed")
	}
}

func TestUDPClientTableDuplicateBindingDoesNotRetainTwice(t *testing.T) {
	var table udpClientTable
	client := netip.MustParseAddrPort("127.0.0.1:4001")
	destination := netip.MustParseAddrPort("1.0.0.1:53")
	redirectAddress := netip.MustParseAddr("127.128.0.7")

	table.setBinding(client, destination, redirectAddress, false)
	table.setBinding(client, destination, redirectAddress, false)
	if references := redirectReferenceCount(&table, redirectAddress); references != 1 {
		t.Fatalf("duplicate packet changed redirect references: %d", references)
	}
}

func TestUDPClientTableCachesOriginalByClientAndToken(t *testing.T) {
	var table udpClientTable
	client := netip.MustParseAddrPort("192.168.43.10:4001")
	otherClient := netip.MustParseAddrPort("192.168.43.11:4001")
	destination := netip.MustParseAddrPort("1.0.0.1:53")
	redirectAddress := netip.MustParseAddr("127.128.0.7")

	if _, loaded := table.cachedOriginal(client, redirectAddress); loaded {
		t.Fatal("original destination was cached before binding")
	}
	table.setBinding(client, destination, redirectAddress, false)
	cached, loaded := table.cachedOriginal(client, redirectAddress)
	if !loaded || cached.original.Destination != destination {
		t.Fatalf("unexpected cached original destination: %+v, %v", cached, loaded)
	}
	if _, loaded = table.cachedOriginal(otherClient, redirectAddress); loaded {
		t.Fatal("original destination cache leaked to another client")
	}
	state, _ := table.load(client)
	table.delete(client, state)
	if _, loaded = table.cachedOriginal(client, redirectAddress); loaded {
		t.Fatal("original destination cache survived session deletion")
	}
}

func TestUDPClientTableConcurrentReleaseSelectsRedirectOnce(t *testing.T) {
	var table udpClientTable
	destination := netip.MustParseAddrPort("8.8.4.4:53")
	redirectAddress := netip.MustParseAddr("127.128.0.8")
	const clientCount = 64
	clients := make([]netip.AddrPort, clientCount)
	states := make([]*udpClientState, clientCount)
	for index := range clients {
		clients[index] = netip.AddrPortFrom(
			netip.AddrFrom4([4]byte{127, 0, 0, 1}),
			uint16(5000+index),
		)
		table.setBinding(clients[index], destination, redirectAddress, false)
		states[index], _ = table.load(clients[index])
	}

	releases := make(chan netip.Addr, clientCount)
	var waitGroup sync.WaitGroup
	for index := range clients {
		waitGroup.Add(1)
		go func(index int) {
			defer waitGroup.Done()
			for _, released := range table.delete(clients[index], states[index]) {
				releases <- released
			}
		}(index)
	}
	waitGroup.Wait()
	close(releases)
	var releaseCount int
	for released := range releases {
		if released != redirectAddress {
			t.Fatalf("unexpected redirect released: %v", released)
		}
		releaseCount++
	}
	if releaseCount != 1 {
		t.Fatalf("redirect selected for deletion %d times", releaseCount)
	}
}

func redirectReferenceCount(table *udpClientTable, redirectAddress netip.Addr) uint32 {
	table.redirectAccess.Lock()
	defer table.redirectAccess.Unlock()
	return table.redirectReferences[udpRedirectReference{address: redirectAddress}]
}
