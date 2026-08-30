//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net/netip"
	"testing"
	"unsafe"
)

func TestTCABI(t *testing.T) {
	if size := unsafe.Sizeof(tcControl{}); size != 72 {
		t.Fatalf("unexpected TC control size: %d", size)
	}
	if offset := unsafe.Offsetof(tcControl{}.RoutingMark); offset != 12 {
		t.Fatalf("unexpected TC routing mark offset: %d", offset)
	}
	if size := unsafe.Sizeof(tcAssignKey{}); size != 44 {
		t.Fatalf("unexpected TC assignment key size: %d", size)
	}
	if size := unsafe.Sizeof(TCAssignment{}); size != 24 {
		t.Fatalf("unexpected TC assignment value size: %d", size)
	}
	if offset := unsafe.Offsetof(TCAssignment{}.SocketCookie); offset != 0 {
		t.Fatalf("unexpected TC assignment socket cookie offset: %d", offset)
	}
}

func TestTCIPv6PathFlags(t *testing.T) {
	localFlags := tcFlags(TCConfig{EnableLocalIPv6: true}, false, false)
	if localFlags&tcFlagLocalIPv6 == 0 || localFlags&tcFlagSharedIPv6 != 0 {
		t.Fatalf("unexpected local IPv6 flags: %#x", localFlags)
	}
	sharedFlags := tcFlags(TCConfig{EnableSharedIPv6: true}, false, false)
	if sharedFlags&tcFlagLocalIPv6 != 0 || sharedFlags&tcFlagSharedIPv6 == 0 {
		t.Fatalf("unexpected shared IPv6 flags: %#x", sharedFlags)
	}
	hybridFlags := tcFlags(TCConfig{EnableLocalIPv6: true, EnableSharedIPv6: true}, false, false)
	if hybridFlags&(tcFlagLocalIPv6|tcFlagSharedIPv6) != tcFlagLocalIPv6|tcFlagSharedIPv6 {
		t.Fatalf("unexpected hybrid IPv6 flags: %#x", hybridFlags)
	}
}

func TestMakeTCAssignKey(t *testing.T) {
	for _, test := range []struct {
		source      string
		destination string
		family      uint8
	}{
		{"192.0.2.10:12345", "1.1.1.1:443", addressFamilyIPv4},
		{"[2001:db8::10]:12345", "[2606:4700:4700::1111]:443", addressFamilyIPv6},
	} {
		source := netip.MustParseAddrPort(test.source)
		destination := netip.MustParseAddrPort(test.destination)
		key, err := makeTCAssignKey(ProtocolTCP, source, destination, 17)
		if err != nil {
			t.Fatal(err)
		}
		if key.Family != test.family || key.Protocol != ProtocolTCP ||
			key.SourcePort != source.Port() || key.DestinationPort != destination.Port() || key.InterfaceIndex != 17 {
			t.Fatalf("unexpected TC assignment key: %+v", key)
		}
		if got := tcKeyAddress(key.Family, key.SourceAddress); got != source.Addr() {
			t.Fatalf("unexpected source address: %s", got)
		}
		if got := tcKeyAddress(key.Family, key.DestinationAddress); got != destination.Addr() {
			t.Fatalf("unexpected destination address: %s", got)
		}
	}
	if _, err := makeTCAssignKey(
		ProtocolUDP,
		netip.MustParseAddrPort("192.0.2.1:1"),
		netip.MustParseAddrPort("[2001:db8::1]:2"),
		0,
	); err == nil {
		t.Fatal("mixed address families were accepted")
	}
}

func tcKeyAddress(family uint8, address [16]byte) netip.Addr {
	if family == addressFamilyIPv4 {
		return netip.AddrFrom4([4]byte(address[:4]))
	}
	return netip.AddrFrom16(address)
}
