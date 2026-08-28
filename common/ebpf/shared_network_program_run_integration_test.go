//go:build with_ebpf && linux && ebpf_integration

package ebpf

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	CiliumEBPF "github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

const (
	testEthernetHeaderLength = 14
	testIPv4HeaderLength     = 20
	testTCPHeaderLength      = 20
	testUDPHeaderLength      = 8
	testTCActOK              = uint32(0)
	testTCActShot            = uint32(2)
	testTCActUnspec          = ^uint32(0)
)

func TestSharedNetworkProgramRunIntegration(t *testing.T) {
	requireEBPFIntegration(t, "run shared-network programs in the kernel")
	backend, err := PrepareSharedNetwork(nil, SharedNetworkConfig{
		ListenerPort:         65531,
		EnableTCP:            true,
		EnableUDP:            true,
		DNSMode:              DNSModeRespectPolicy,
		BypassPrivateAddress: true,
		RedirectIPv4:         netip.MustParsePrefix("127.128.0.0/9"),
		RedirectIPv6:         netip.MustParsePrefix("fd53:696e:672d:626f::/64"),
		FakeIPIPv4:           netip.MustParsePrefix("198.18.0.0/15"),
		IncludeSourceMAC:     []MACAddress{{0x02, 0, 0, 0, 0, 1}},
		MapCapacity:          DefaultSharedNetworkMapCapacities(),
		UDPTimeout:           5 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	if err = backend.Enable(); err != nil {
		t.Fatal(err)
	}
	ingress := backend.runtime.programs[sharedNetworkProgramIngress]
	egress := backend.runtime.programs[sharedNetworkProgramEgress]

	t.Run("policy_priority", func(t *testing.T) {
		privateDNS := testIPv4TCPPacket(
			netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("192.168.1.1"), 53000, 53,
		)
		action, output := runSharedNetworkProgram(t, ingress, privateDNS)
		if action != testTCActOK {
			t.Fatalf("respect_policy did not rewrite selected private DNS: action=%d", action)
		}
		assertIPv4TCPRewrite(t, output, netip.MustParseAddr("127.128.0.0"), 9, 65531)

		unselectedDNS := testIPv4TCPPacket(
			netip.MustParseAddr("192.0.2.11"), netip.MustParseAddr("192.168.1.1"), 53002, 53,
		)
		unselectedDNS[11] = 2
		action, output = runSharedNetworkProgram(t, ingress, unselectedDNS)
		if action != testTCActUnspec || string(output) != string(unselectedDNS) {
			t.Fatalf("respect_policy did not bypass unselected source DNS: action=%d", action)
		}

		backend.control.DNSMode = DNSModeHijack
		if err := backend.updateControl(); err != nil {
			t.Fatal(err)
		}
		action, output = runSharedNetworkProgram(t, ingress, privateDNS)
		if action != testTCActOK {
			t.Fatalf("hijack DNS was not rewritten: action=%d", action)
		}
		assertIPv4TCPRewrite(t, output, netip.MustParseAddr("127.128.0.0"), 9, 65531)

		backend.control.DNSMode = DNSModeRespectPolicy
		if err := backend.updateControl(); err != nil {
			t.Fatal(err)
		}
		fakeIP := testIPv4TCPPacket(
			netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("198.18.1.1"), 53001, 443,
		)
		action, output = runSharedNetworkProgram(t, ingress, fakeIP)
		if action != testTCActOK {
			t.Fatalf("FakeIP was not prioritized over private bypass: action=%d", action)
		}
		assertIPv4TCPRewrite(t, output, netip.MustParseAddr("127.128.0.0"), 9, 65531)
	})

	t.Run("fragment_ingress_bypass", func(t *testing.T) {
		first := testIPv4UDPFragment(
			netip.MustParseAddr("192.0.2.20"), netip.MustParseAddr("203.0.113.20"),
			54000, 443, 0x4242, 0, true, []byte("first-fragment"),
		)
		later := testIPv4UDPFragment(
			netip.MustParseAddr("192.0.2.20"), netip.MustParseAddr("203.0.113.20"),
			0, 0, 0x4242, 2, false, []byte("later-fragment"),
		)
		for name, packet := range map[string][]byte{
			"IPv4 first fragment": first,
			"IPv4 later fragment": later,
		} {
			t.Run(name, func(t *testing.T) {
				action, output := runSharedNetworkProgram(t, ingress, packet)
				if action != testTCActUnspec || string(output) != string(packet) {
					t.Fatalf("fragment was not bypassed unchanged: action=%d", action)
				}
			})
		}

		for name, fragment := range map[string]uint16{
			"IPv6 first fragment": 1,
			"IPv6 later fragment": 8,
		} {
			t.Run(name, func(t *testing.T) {
				packet := testIPv6TCPPacket(
					netip.MustParseAddr("2001:db8::10"),
					netip.MustParseAddr("2001:4860:4860::8888"),
					53000,
					443,
					&fragment,
				)
				action, output := runSharedNetworkProgram(t, ingress, packet)
				if action != testTCActUnspec || string(output) != string(packet) {
					t.Fatalf("fragment was not bypassed unchanged: action=%d", action)
				}
			})
		}
	})

	t.Run("token_fragment_egress_drop", func(t *testing.T) {
		first := testIPv4UDPFragment(
			netip.MustParseAddr("127.128.0.1"), netip.MustParseAddr("192.0.2.20"),
			65531, 54000, 0x4242, 0, true, []byte("first-fragment"),
		)
		later := testIPv4UDPFragment(
			netip.MustParseAddr("127.128.0.1"), netip.MustParseAddr("192.0.2.20"),
			0, 0, 0x4242, 2, false, []byte("later-fragment"),
		)
		for name, packet := range map[string][]byte{
			"IPv4 first fragment": first,
			"IPv4 later fragment": later,
		} {
			t.Run(name, func(t *testing.T) {
				action, _ := runSharedNetworkProgram(t, egress, packet)
				if action != testTCActShot {
					t.Fatalf("token fragment did not fail closed: action=%d", action)
				}
			})
		}

		for name, fragment := range map[string]uint16{
			"IPv6 first fragment": 1,
			"IPv6 later fragment": 8,
		} {
			t.Run(name, func(t *testing.T) {
				packet := testIPv6TCPPacket(
					netip.MustParseAddr("fd53:696e:672d:626f::1"),
					netip.MustParseAddr("2001:db8::10"),
					65531,
					53000,
					&fragment,
				)
				action, _ := runSharedNetworkProgram(t, egress, packet)
				if action != testTCActShot {
					t.Fatalf("token fragment did not fail closed: action=%d", action)
				}
			})
		}
	})

	t.Run("IPv6_atomic_fragment", func(t *testing.T) {
		atomicFragment := uint16(0)
		packet := testIPv6TCPPacket(
			netip.MustParseAddr("2001:db8::10"),
			netip.MustParseAddr("2001:4860:4860::8888"),
			53000,
			443,
			&atomicFragment,
		)
		action, output := runSharedNetworkProgram(t, ingress, packet)
		if action != testTCActOK {
			t.Fatalf("atomic fragment was not parsed as a normal packet: action=%d", action)
		}
		destination := netip.AddrFrom16([16]byte(output[38:54]))
		if !netip.MustParsePrefix("fd53:696e:672d:626f::/64").Contains(destination) {
			t.Fatalf("atomic fragment destination was not rewritten: %s", destination)
		}
		if got := binary.BigEndian.Uint16(output[64:66]); got != 65531 {
			t.Fatalf("atomic fragment destination port was not rewritten: %d", got)
		}
	})

	t.Run("fail_closed", func(t *testing.T) {
		malformed := testIPv4TCPPacket(
			netip.MustParseAddr("192.0.2.40"), netip.MustParseAddr("203.0.113.40"), 55000, 443,
		)[:testEthernetHeaderLength+testIPv4HeaderLength+2]
		action, _ := runSharedNetworkProgram(t, ingress, malformed)
		if action != testTCActShot {
			t.Fatalf("truncated selected packet did not fail closed: action=%d", action)
		}
	})
}

func runSharedNetworkProgram(t *testing.T, program *CiliumEBPF.Program, packet []byte) (uint32, []byte) {
	t.Helper()
	output := make([]byte, len(packet)+256)
	options := &CiliumEBPF.RunOptions{Data: packet, DataOut: output, Repeat: 1}
	action, err := program.Run(options)
	if err != nil {
		t.Fatal(err)
	}
	if len(options.DataOut) < len(packet) {
		t.Fatalf("short program output: %d < %d", len(options.DataOut), len(packet))
	}
	return action, options.DataOut[:len(packet)]
}

func testIPv4TCPPacket(source, destination netip.Addr, sourcePort, destinationPort uint16) []byte {
	packet := testIPv4Packet(source, destination, unix.IPPROTO_TCP, testTCPHeaderLength, 0, 0)
	tcp := packet[testEthernetHeaderLength+testIPv4HeaderLength:]
	binary.BigEndian.PutUint16(tcp[0:2], sourcePort)
	binary.BigEndian.PutUint16(tcp[2:4], destinationPort)
	binary.BigEndian.PutUint32(tcp[4:8], 1)
	tcp[12] = 5 << 4
	tcp[13] = 0x02
	binary.BigEndian.PutUint16(tcp[14:16], 65535)
	binary.BigEndian.PutUint16(tcp[16:18], transportChecksumIPv4(source, destination, unix.IPPROTO_TCP, tcp))
	return packet
}

func testIPv6TCPPacket(
	source, destination netip.Addr,
	sourcePort, destinationPort uint16,
	fragment *uint16,
) []byte {
	const (
		ipv6HeaderLength     = 40
		fragmentHeaderLength = 8
	)
	transportOffset := testEthernetHeaderLength + ipv6HeaderLength
	payloadLength := testTCPHeaderLength
	if fragment != nil {
		transportOffset += fragmentHeaderLength
		payloadLength += fragmentHeaderLength
	}
	packet := make([]byte, testEthernetHeaderLength+ipv6HeaderLength+payloadLength)
	copy(packet[0:6], []byte{0x02, 0, 0, 0, 0, 2})
	copy(packet[6:12], []byte{0x02, 0, 0, 0, 0, 1})
	binary.BigEndian.PutUint16(packet[12:14], unix.ETH_P_IPV6)
	ip := packet[testEthernetHeaderLength:]
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:6], uint16(payloadLength))
	ip[6] = unix.IPPROTO_TCP
	ip[7] = 64
	if fragment != nil {
		ip[6] = unix.IPPROTO_FRAGMENT
		fragmentHeader := ip[ipv6HeaderLength:]
		fragmentHeader[0] = unix.IPPROTO_TCP
		binary.BigEndian.PutUint16(fragmentHeader[2:4], *fragment)
		binary.BigEndian.PutUint32(fragmentHeader[4:8], 0x42424242)
	}
	source6 := source.As16()
	destination6 := destination.As16()
	copy(ip[8:24], source6[:])
	copy(ip[24:40], destination6[:])
	tcp := packet[transportOffset:]
	binary.BigEndian.PutUint16(tcp[0:2], sourcePort)
	binary.BigEndian.PutUint16(tcp[2:4], destinationPort)
	tcp[12] = 5 << 4
	tcp[13] = 0x02
	return packet
}

func testIPv4UDPFragment(
	source, destination netip.Addr,
	sourcePort, destinationPort, identification, fragmentOffset uint16,
	more bool,
	payload []byte,
) []byte {
	headerLength := 0
	if fragmentOffset == 0 {
		headerLength = testUDPHeaderLength
	}
	fragment := fragmentOffset & 0x1fff
	if more {
		fragment |= 0x2000
	}
	packet := testIPv4Packet(source, destination, unix.IPPROTO_UDP, headerLength+len(payload), identification, fragment)
	transport := packet[testEthernetHeaderLength+testIPv4HeaderLength:]
	if fragmentOffset == 0 {
		binary.BigEndian.PutUint16(transport[0:2], sourcePort)
		binary.BigEndian.PutUint16(transport[2:4], destinationPort)
		binary.BigEndian.PutUint16(transport[4:6], uint16(testUDPHeaderLength+len(payload)))
		copy(transport[testUDPHeaderLength:], payload)
	} else {
		copy(transport, payload)
	}
	return packet
}

func testIPv4Packet(
	source, destination netip.Addr,
	protocol uint8,
	payloadLength int,
	identification, fragment uint16,
) []byte {
	packet := make([]byte, testEthernetHeaderLength+testIPv4HeaderLength+payloadLength)
	copy(packet[0:6], []byte{0x02, 0, 0, 0, 0, 2})
	copy(packet[6:12], []byte{0x02, 0, 0, 0, 0, 1})
	binary.BigEndian.PutUint16(packet[12:14], unix.ETH_P_IP)
	ip := packet[testEthernetHeaderLength:]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(testIPv4HeaderLength+payloadLength))
	binary.BigEndian.PutUint16(ip[4:6], identification)
	binary.BigEndian.PutUint16(ip[6:8], fragment)
	ip[8] = 64
	ip[9] = protocol
	source4 := source.As4()
	destination4 := destination.As4()
	copy(ip[12:16], source4[:])
	copy(ip[16:20], destination4[:])
	binary.BigEndian.PutUint16(ip[10:12], checksum16(ip[:testIPv4HeaderLength]))
	return packet
}

func assertIPv4TCPRewrite(t *testing.T, packet []byte, prefix netip.Addr, prefixBits int, port uint16) {
	t.Helper()
	destination := netip.AddrFrom4([4]byte(packet[30:34]))
	if !netip.PrefixFrom(prefix, prefixBits).Contains(destination) {
		t.Fatalf("destination was not rewritten into token prefix: %s", destination)
	}
	if got := binary.BigEndian.Uint16(packet[36:38]); got != port {
		t.Fatalf("destination port was not rewritten: %d", got)
	}
	ip := packet[testEthernetHeaderLength : testEthernetHeaderLength+testIPv4HeaderLength]
	if checksum16(ip) != 0 {
		t.Fatal("rewritten packet has an invalid IPv4 checksum")
	}
	tcp := packet[testEthernetHeaderLength+testIPv4HeaderLength:]
	source := netip.AddrFrom4([4]byte(ip[12:16]))
	if transportChecksumIPv4(source, destination, unix.IPPROTO_TCP, tcp) != 0 {
		t.Fatal("rewritten packet has an invalid TCP checksum")
	}
}

func transportChecksumIPv4(source, destination netip.Addr, protocol uint8, payload []byte) uint16 {
	pseudo := make([]byte, 12+len(payload))
	source4 := source.As4()
	destination4 := destination.As4()
	copy(pseudo[0:4], source4[:])
	copy(pseudo[4:8], destination4[:])
	pseudo[9] = protocol
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(payload)))
	copy(pseudo[12:], payload)
	return checksum16(pseudo)
}

func checksum16(data []byte) uint16 {
	var sum uint32
	for len(data) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(data[:2]))
		data = data[2:]
	}
	if len(data) == 1 {
		sum += uint32(data[0]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}
