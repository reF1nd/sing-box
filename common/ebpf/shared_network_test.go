//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net/netip"
	"testing"
	"time"
	"unsafe"
)

func TestSharedNetworkABI(t *testing.T) {
	if size := unsafe.Sizeof(sharedNetworkControl{}); size != 80 {
		t.Fatalf("unexpected shared-network control size: %d", size)
	}
	if size := unsafe.Sizeof(sharedNetworkListenerKey{}); size != 40 {
		t.Fatalf("unexpected shared-network listener key size: %d", size)
	}
	if size := unsafe.Sizeof(sharedNetworkOriginalKey{}); size != 44 {
		t.Fatalf("unexpected shared-network original key size: %d", size)
	}
	if size := unsafe.Sizeof(sharedNetworkMACKey{}); size != 8 {
		t.Fatalf("unexpected shared-network MAC key size: %d", size)
	}
	if size := unsafe.Sizeof(sharedNetworkReplyKey{}); size != 44 {
		t.Fatalf("unexpected shared-network reply key size: %d", size)
	}
	if size := unsafe.Sizeof(sharedNetworkOriginalValue{}); size != 36 {
		t.Fatalf("unexpected shared-network original value size: %d", size)
	}
	if size := unsafe.Sizeof(sharedNetworkTokenValue{}); size != 40 {
		t.Fatalf("unexpected shared-network token value size: %d", size)
	}
	if sharedNetworkFlagDNSHijack != 1<<4 {
		t.Fatalf("unexpected shared-network DNS flag: %#x", sharedNetworkFlagDNSHijack)
	}
	if sharedNetworkFlagBypassPrivateAddress != 1<<13 {
		t.Fatalf("unexpected shared-network private-address flag: %#x", sharedNetworkFlagBypassPrivateAddress)
	}
	if sharedNetworkFlagBypassFlowCache != 1<<14 {
		t.Fatalf("unexpected shared-network bypass-flow-cache flag: %#x", sharedNetworkFlagBypassFlowCache)
	}
	if sharedNetworkFlagDNSRespectBypass != 1<<15 {
		t.Fatalf("unexpected shared-network DNS respect-bypass flag: %#x", sharedNetworkFlagDNSRespectBypass)
	}
	if sharedNetworkFlagFakeIPIPv4 != 1<<16 || sharedNetworkFlagFakeIPIPv6 != 1<<17 {
		t.Fatalf(
			"unexpected shared-network FakeIP flags: IPv4=%#x IPv6=%#x",
			sharedNetworkFlagFakeIPIPv4,
			sharedNetworkFlagFakeIPIPv6,
		)
	}
	if sharedNetworkPolicyFlags != 0x5fe0 {
		t.Fatalf("unexpected shared-network policy flags: %#x", sharedNetworkPolicyFlags)
	}
}

func TestSharedNetworkBypassFlowCacheRequired(t *testing.T) {
	if sharedNetworkBypassFlowCacheRequired(0) {
		t.Fatal("empty policy unexpectedly requires bypass-flow cache lookups")
	}
	if sharedNetworkBypassFlowCacheRequired(sharedNetworkFlagHostIPv4) {
		t.Fatal("host-only policy unexpectedly requires bypass-flow cache lookups")
	}
	for _, flags := range []uint32{
		sharedNetworkFlagBypassIPv4,
		sharedNetworkFlagBypassIPv6,
		sharedNetworkFlagIncludeSource,
		sharedNetworkFlagExcludeSource,
		sharedNetworkFlagIncludeSourceMAC,
		sharedNetworkFlagExcludeSourceMAC,
	} {
		if !sharedNetworkBypassFlowCacheRequired(flags) {
			t.Fatalf("policy flags %#x did not enable bypass-flow cache lookups", flags)
		}
	}
}

func TestSharedNetworkUDPTimeoutSeconds(t *testing.T) {
	for _, test := range []struct {
		timeout time.Duration
		seconds uint32
	}{
		{time.Nanosecond, 1},
		{time.Second, 1},
		{1500 * time.Millisecond, 2},
		{5 * time.Minute, 300},
	} {
		seconds, err := sharedNetworkUDPTimeoutSeconds(test.timeout)
		if err != nil {
			t.Fatal(err)
		}
		if seconds != test.seconds {
			t.Fatalf("unexpected timeout conversion for %s: %d", test.timeout, seconds)
		}
		cgroupSeconds, err := cgroupUDPTimeoutSeconds(test.timeout)
		if err != nil {
			t.Fatal(err)
		}
		if cgroupSeconds != test.seconds {
			t.Fatalf("unexpected cgroup timeout conversion for %s: %d", test.timeout, cgroupSeconds)
		}
	}
	for _, timeout := range []time.Duration{0, -time.Second, time.Duration(1<<63 - 1)} {
		if _, err := sharedNetworkUDPTimeoutSeconds(timeout); err == nil {
			t.Fatalf("expected timeout %s to be rejected", timeout)
		}
	}
}

func TestMakeSharedNetworkFlowHandle(t *testing.T) {
	client := netip.MustParseAddrPort("192.168.43.10:53000")
	tokenDestination := netip.MustParseAddrPort("127.200.1.2:65531")
	key, err := makeSharedNetworkListenerKey(ProtocolUDP, client, tokenDestination)
	if err != nil {
		t.Fatal(err)
	}
	original := netip.MustParseAddrPort("1.1.1.1:53")
	value := sharedNetworkOriginalValue{
		Family:         addressFamilyIPv4,
		Protocol:       ProtocolUDP,
		Port:           original.Port(),
		InterfaceIndex: 42,
		SourceMAC:      [6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
	}
	copy(value.Addr[:], original.Addr().AsSlice())
	flow := makeSharedNetworkFlowHandle(key, value)
	if flow.originalKey.InterfaceIndex != 42 ||
		flow.originalKey.OriginalPort != original.Port() ||
		flow.replyKey.InterfaceIndex != 42 ||
		flow.replyKey.ListenerPort != tokenDestination.Port() ||
		flow.listenerKey != key {
		t.Fatalf("unexpected shared-network flow: %+v", flow)
	}
	if actual := sharedNetworkOriginalMAC(value); actual.String() != "02:00:00:00:00:01" {
		t.Fatalf("unexpected source MAC: %s", actual)
	}
	fromOriginal := makeSharedNetworkFlowHandleFromOriginal(flow.originalKey, flow.listenerKey.TokenAddr, tokenDestination.Port())
	if fromOriginal != flow {
		t.Fatalf("reconstructed shared-network flow differs: got=%+v want=%+v", fromOriginal, flow)
	}
}

func TestMakeSharedNetworkListenerKey(t *testing.T) {
	client := netip.MustParseAddrPort("192.168.43.10:53000")
	tokenDestination := netip.MustParseAddrPort("127.200.1.2:65531")
	key, err := makeSharedNetworkListenerKey(ProtocolUDP, client, tokenDestination)
	if err != nil {
		t.Fatal(err)
	}
	if key.Family != addressFamilyIPv4 || key.Protocol != ProtocolUDP ||
		key.ClientPort != client.Port() || key.ListenerPort != tokenDestination.Port() {
		t.Fatalf("unexpected listener key: %+v", key)
	}
	if got := netip.AddrFrom4([4]byte(key.ClientAddr[:4])); got != client.Addr() {
		t.Fatalf("unexpected client address: %s", got)
	}
	if got := netip.AddrFrom4([4]byte(key.TokenAddr[:4])); got != tokenDestination.Addr() {
		t.Fatalf("unexpected token address: %s", got)
	}
	_, err = makeSharedNetworkListenerKey(
		ProtocolUDP,
		client,
		netip.MustParseAddrPort("[fd53:696e:672d:626f::1]:65531"),
	)
	if err == nil {
		t.Fatal("expected mixed address families to be rejected")
	}
}

func TestCompileSharedHostPrefixes(t *testing.T) {
	ipv4, ipv6 := compileHostPrefixes([]netip.Addr{
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
