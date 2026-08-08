package ebpf

import (
	"net/netip"
	"testing"
	"unsafe"
)

func TestCgroupRedirectABI(t *testing.T) {
	if size := unsafe.Sizeof(listenerLookupKey{}); size != 20 {
		t.Fatalf("unexpected redirect key size: %d", size)
	}
	if size := unsafe.Sizeof(originalDestinationValue{}); size != 32 {
		t.Fatalf("unexpected original destination size: %d", size)
	}
	if offset := unsafe.Offsetof(listenerLookupKey{}.TokenAddr); offset != 4 {
		t.Fatalf("unexpected redirect address offset: %d", offset)
	}
	if offset := unsafe.Offsetof(originalDestinationValue{}.Addr); offset != 4 {
		t.Fatalf("unexpected original address offset: %d", offset)
	}
	if offset := unsafe.Offsetof(originalDestinationValue{}.Flags); offset != 20 {
		t.Fatalf("unexpected original flags offset: %d", offset)
	}
	if offset := unsafe.Offsetof(originalDestinationValue{}.SocketCookie); offset != 24 {
		t.Fatalf("unexpected socket cookie offset: %d", offset)
	}
	if size := unsafe.Sizeof(udpFlowKey{}); size != 32 {
		t.Fatalf("unexpected UDP flow key size: %d", size)
	}
	if size := unsafe.Sizeof(udpFlowValue{}); size != 32 {
		t.Fatalf("unexpected UDP flow value size: %d", size)
	}
	key, err := makeListenerLookupKey(
		ProtocolUDP,
		netip.MustParseAddrPort("[::ffff:127.2.3.4]:65532"),
	)
	if err != nil {
		t.Fatal(err)
	}
	if key.Family != addressFamilyIPv4 || key.ListenerPort != 65532 {
		t.Fatalf("unexpected redirect key header: %+v", key)
	}
	if [4]byte(key.TokenAddr[:4]) != [4]byte{127, 2, 3, 4} {
		t.Fatalf("unexpected redirect address: %v", key.TokenAddr)
	}
}

func TestBypassCIDRABI(t *testing.T) {
	if size := unsafe.Sizeof(ipv4CIDRLPMKey{}); size != 8 {
		t.Fatalf("unexpected IPv4 CIDR LPM key size: %d", size)
	}
	if size := unsafe.Sizeof(ipv6CIDRLPMKey{}); size != 20 {
		t.Fatalf("unexpected IPv6 CIDR LPM key size: %d", size)
	}
}
