//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net/netip"
	"sync"
	"testing"
)

func TestUDPConnectedBindingIgnoresOutboundEndpoint(t *testing.T) {
	var table udpClientTable
	client := netip.MustParseAddrPort("127.0.0.1:1234")
	destination := netip.MustParseAddrPort("43.173.131.13:443")
	redirectAddress := netip.MustParseAddr("127.128.0.1")
	outboundEndpoints := []netip.AddrPort{
		netip.MustParseAddrPort("43.173.131.13:32080"),
		netip.MustParseAddrPort("43.153.249.207:5000"),
	}

	table.setBinding(client, destination, redirectAddress, true)
	clientState, loaded := table.load(client)
	if !loaded {
		t.Fatal("client state was not created")
	}
	clientState.setConnected(true, destination)
	for _, outboundEndpoint := range outboundEndpoints {
		binding, loaded := clientState.redirectBinding(outboundEndpoint)
		if !loaded || binding.address != redirectAddress {
			t.Fatalf("connected binding was not used for %v: %+v, %v", outboundEndpoint, binding, loaded)
		}
	}

	clientState.setConnected(false, netip.AddrPort{})
	if _, loaded = clientState.redirectBinding(outboundEndpoints[0]); loaded {
		t.Fatal("unconnected lookup ignored the packet destination")
	}
	if _, loaded = clientState.redirectBinding(destination); !loaded {
		t.Fatal("unconnected exact lookup lost the redirect binding")
	}
}

func TestUDPConnectedBindingConcurrentReplacement(t *testing.T) {
	var table udpClientTable
	client := netip.MustParseAddrPort("127.0.0.1:1234")
	destination := netip.MustParseAddrPort("43.173.131.13:443")
	redirectAddresses := []netip.Addr{
		netip.MustParseAddr("127.128.0.1"),
		netip.MustParseAddr("127.128.0.2"),
	}
	table.setBinding(client, destination, redirectAddresses[0], true)
	clientState, _ := table.load(client)
	clientState.setConnected(true, destination)

	const iterations = 1000
	var waitGroup sync.WaitGroup
	waitGroup.Add(2)
	go func() {
		defer waitGroup.Done()
		for index := range iterations {
			table.setBinding(client, destination, redirectAddresses[index%2], true)
		}
	}()
	go func() {
		defer waitGroup.Done()
		for range iterations {
			binding, loaded := clientState.redirectBinding(netip.MustParseAddrPort("192.0.2.1:5000"))
			if !loaded || (binding.address != redirectAddresses[0] && binding.address != redirectAddresses[1]) {
				t.Errorf("unexpected connected binding: %+v, loaded=%v", binding, loaded)
				return
			}
		}
	}()
	waitGroup.Wait()
}

func BenchmarkUDPConnectedBinding(b *testing.B) {
	var table udpClientTable
	client := netip.MustParseAddrPort("127.0.0.1:9001")
	destination := netip.MustParseAddrPort("43.173.131.13:443")
	outboundEndpoint := netip.MustParseAddrPort("43.153.249.207:5000")
	redirectAddress := netip.MustParseAddr("127.128.0.9")
	table.setBinding(client, destination, redirectAddress, true)
	clientState, _ := table.load(client)
	clientState.setConnected(true, destination)

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		binding, loaded := clientState.redirectBinding(outboundEndpoint)
		if !loaded || binding.address != redirectAddress {
			b.Fatal("connected redirect binding was lost")
		}
	}
}
