//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net/netip"
	"testing"
	"unsafe"
)

func TestCgroupRedirectABI(t *testing.T) {
	if size := unsafe.Sizeof(cgroupControl{}); size != 72 {
		t.Fatalf("unexpected cgroup control size: %d", size)
	}
	if size := unsafe.Sizeof(listenerLookupKey{}); size != 20 {
		t.Fatalf("unexpected redirect key size: %d", size)
	}
	if size := unsafe.Sizeof(originalDestinationValue{}); size != 40 {
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
	if offset := unsafe.Offsetof(originalDestinationValue{}.CreatedAtNS); offset != 32 {
		t.Fatalf("unexpected creation time offset: %d", offset)
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

func TestOriginalDestinationFromValue(t *testing.T) {
	testCases := []struct {
		name     string
		value    originalDestinationValue
		expected netip.AddrPort
	}{
		{
			name: "IPv4",
			value: originalDestinationValue{
				Family: addressFamilyIPv4,
				Port:   5353,
				Addr:   [16]byte{198, 51, 100, 20},
			},
			expected: netip.MustParseAddrPort("198.51.100.20:5353"),
		},
		{
			name: "IPv6",
			value: func() originalDestinationValue {
				value := originalDestinationValue{Family: addressFamilyIPv6, Port: 443, Flags: 1}
				value.Addr = netip.MustParseAddr("2001:db8::1").As16()
				return value
			}(),
			expected: netip.MustParseAddrPort("[2001:db8::1]:443"),
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			actual, err := originalDestinationFromValue(testCase.value)
			if err != nil {
				t.Fatal(err)
			}
			if actual.Destination != testCase.expected {
				t.Fatalf("unexpected destination: %v", actual.Destination)
			}
			if actual.ConnectedUDP != (testCase.value.Flags&1 != 0) {
				t.Fatalf("unexpected connected UDP flag: %v", actual.ConnectedUDP)
			}
		})
	}
}

func TestOriginalDestinationFromUDPPeer(t *testing.T) {
	peer := udpPeerValue{
		Family:   addressFamilyIPv4,
		Protocol: ProtocolUDP,
		Port:     53,
	}
	copy(peer.Addr[:4], netip.MustParseAddr("192.0.2.53").AsSlice())
	value, err := originalDestinationFromUDPPeer(42, peer)
	if err != nil {
		t.Fatal(err)
	}
	original, err := originalDestinationFromValue(value)
	if err != nil {
		t.Fatal(err)
	}
	if original.Destination != netip.MustParseAddrPort("192.0.2.53:53") ||
		!original.ConnectedUDP || value.SocketCookie != 42 {
		t.Fatalf("unexpected connected UDP original destination: %+v", value)
	}

	invalid := []udpPeerValue{
		{},
		{Family: addressFamilyIPv4, Protocol: ProtocolTCP, Port: 53, Addr: peer.Addr},
		{Family: addressFamilyIPv4, Protocol: ProtocolUDP, Addr: peer.Addr},
		{Family: addressFamilyIPv4, Protocol: ProtocolUDP, Port: 53},
		{Family: 255, Protocol: ProtocolUDP, Port: 53, Addr: peer.Addr},
	}
	for _, invalidPeer := range invalid {
		if _, err = originalDestinationFromUDPPeer(42, invalidPeer); err == nil {
			t.Fatalf("accepted invalid connected UDP peer: %+v", invalidPeer)
		}
	}
	if _, err = originalDestinationFromUDPPeer(0, peer); err == nil {
		t.Fatal("accepted an empty connected UDP socket cookie")
	}
}
