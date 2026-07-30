//go:build with_ebpf && (linux || android) && cgo

package ebpf

import (
	"net/netip"
	"testing"
	"unsafe"
)

func TestSharedNetworkABI(t *testing.T) {
	if size := unsafe.Sizeof(sharedNetworkControl{}); size != 36 {
		t.Fatalf("unexpected shared-network control size: %d", size)
	}
	if size := unsafe.Sizeof(sharedNetworkRedirectKey{}); size != 40 {
		t.Fatalf("unexpected shared-network redirect key size: %d", size)
	}
	if sharedNetworkFlagDNSHijack != 1<<4 {
		t.Fatalf("unexpected shared-network DNS flag: %#x", sharedNetworkFlagDNSHijack)
	}
}

func TestMakeSharedNetworkRedirectKey(t *testing.T) {
	client := netip.MustParseAddrPort("192.168.43.10:53000")
	redirect := netip.MustParseAddrPort("127.200.1.2:65531")
	key, err := makeSharedNetworkRedirectKey(ProtocolUDP, client, redirect)
	if err != nil {
		t.Fatal(err)
	}
	if key.Family != addressFamilyIPv4 || key.Protocol != ProtocolUDP ||
		key.ClientPort != client.Port() || key.RedirectPort != redirect.Port() {
		t.Fatalf("unexpected redirect key: %+v", key)
	}
	if got := netip.AddrFrom4([4]byte(key.ClientAddr[:4])); got != client.Addr() {
		t.Fatalf("unexpected client address: %s", got)
	}
	if got := netip.AddrFrom4([4]byte(key.RedirectAddr[:4])); got != redirect.Addr() {
		t.Fatalf("unexpected redirect address: %s", got)
	}
	_, err = makeSharedNetworkRedirectKey(
		ProtocolUDP,
		client,
		netip.MustParseAddrPort("[fd53:696e:672d:626f::1]:65531"),
	)
	if err == nil {
		t.Fatal("expected mixed address families to be rejected")
	}
}

func TestCompileSharedHostPrefixes(t *testing.T) {
	ipv4, ipv6 := compileSharedHostPrefixes([]netip.Addr{
		netip.MustParseAddr("192.0.2.2"),
		netip.MustParseAddr("192.0.2.1"),
		netip.MustParseAddr("192.0.2.2"),
		netip.MustParseAddr("2001:db8::1"),
		netip.MustParseAddr("::ffff:192.0.2.3"),
	})
	wantIPv4 := []netip.Prefix{
		netip.MustParsePrefix("192.0.2.1/32"),
		netip.MustParsePrefix("192.0.2.2/32"),
		netip.MustParsePrefix("192.0.2.3/32"),
	}
	wantIPv6 := []netip.Prefix{netip.MustParsePrefix("2001:db8::1/128")}
	if len(ipv4) != len(wantIPv4) {
		t.Fatalf("unexpected IPv4 host prefixes: %v", ipv4)
	}
	for index := range wantIPv4 {
		if ipv4[index] != wantIPv4[index] {
			t.Fatalf("unexpected IPv4 host prefixes: %v", ipv4)
		}
	}
	if len(ipv6) != 1 || ipv6[0] != wantIPv6[0] {
		t.Fatalf("unexpected IPv6 host prefixes: %v", ipv6)
	}
}
