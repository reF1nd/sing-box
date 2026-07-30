//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"testing"
	"unsafe"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/common/json/badoption"

	"golang.org/x/sys/unix"
)

func TestNormalizeListenOptionsDefaults(t *testing.T) {
	options, err := normalizeListenOptions(option.ListenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if options.Listen == nil || netip.Addr(*options.Listen) != netip.IPv4Unspecified() {
		t.Fatalf("unexpected listen address: %v", options.Listen)
	}
	if options.ListenPort != defaultListenPort {
		t.Fatalf("unexpected listen port: %d", options.ListenPort)
	}
}

func TestCombineStartError(t *testing.T) {
	startErr := errors.New("start failed")
	if result := combineStartError(startErr, nil); result != startErr {
		t.Fatalf("expected the original start error, got %v", result)
	}
	cleanupErr := errors.New("cleanup failed")
	result := combineStartError(startErr, cleanupErr)
	if !errors.Is(result, startErr) || !errors.Is(result, cleanupErr) {
		t.Fatalf("expected both errors to be retained, got %v", result)
	}
}

func TestNormalizeListenOptionsPreservesFields(t *testing.T) {
	listenAddress := badoption.Addr(netip.IPv6Unspecified())
	options, err := normalizeListenOptions(option.ListenOptions{
		Listen:     &listenAddress,
		ListenPort: 12345,
		ReuseAddr:  true,
		Detour:     "detour-in",
	})
	if err != nil {
		t.Fatal(err)
	}
	if options.Listen == nil || netip.Addr(*options.Listen) != netip.IPv4Unspecified() {
		t.Fatalf("unexpected normalized listen address: %v", options.Listen)
	}
	if options.ListenPort != 12345 || !options.ReuseAddr || options.Detour != "detour-in" {
		t.Fatalf("listen fields were not preserved: %+v", options)
	}
}

func TestNormalizeListenOptionsRejectsSpecificAddress(t *testing.T) {
	listenAddress := badoption.Addr(netip.MustParseAddr("127.0.0.1"))
	_, err := normalizeListenOptions(option.ListenOptions{Listen: &listenAddress})
	if err == nil {
		t.Fatal("expected a specific listen address to be rejected")
	}
}

func TestNormalizeListenOptionsRejectsProxyProtocol(t *testing.T) {
	_, err := normalizeListenOptions(option.ListenOptions{ProxyProtocol: true})
	if err == nil {
		t.Fatal("expected proxy protocol to be rejected")
	}
}

func TestNormalizeListenOptionsRejectsNetworkNamespace(t *testing.T) {
	_, err := normalizeListenOptions(option.ListenOptions{NetNs: "test-netns"})
	if err == nil {
		t.Fatal("expected netns to be rejected")
	}
}

func TestNormalizeListenOptionsAllowsLoopbackBindInterface(t *testing.T) {
	options, err := normalizeListenOptions(option.ListenOptions{BindInterface: "lo"})
	if err != nil {
		t.Fatal(err)
	}
	if options.BindInterface != "lo" {
		t.Fatalf("unexpected bind interface: %s", options.BindInterface)
	}
}

func TestNormalizeListenOptionsRejectsNonLoopbackBindInterface(t *testing.T) {
	_, err := normalizeListenOptions(option.ListenOptions{BindInterface: "wlan0"})
	if err == nil {
		t.Fatal("expected a non-loopback bind_interface to be rejected")
	}
}

func TestNormalizeCgroupPath(t *testing.T) {
	for _, test := range []struct {
		input  string
		output string
	}{
		{"", ""},
		{"/sys/fs/cgroup", "/sys/fs/cgroup"},
		{"/sys/fs/cgroup/user.slice/../system.slice", "/sys/fs/cgroup/system.slice"},
	} {
		output, err := normalizeCgroupPath(test.input)
		if err != nil {
			t.Fatal(err)
		}
		if output != test.output {
			t.Fatalf("unexpected normalized cgroup path: %q", output)
		}
	}
}

func TestNormalizeCgroupPathRejectsRelativePath(t *testing.T) {
	if _, err := normalizeCgroupPath("user.slice/test.scope"); err == nil {
		t.Fatal("expected a relative cgroup path to be rejected")
	}
}

func TestNormalizeDNSMode(t *testing.T) {
	for _, test := range []struct {
		input  string
		output string
	}{
		{"", dnsModeHijack},
		{dnsModeHijack, dnsModeHijack},
		{dnsModeOff, dnsModeOff},
	} {
		output, err := normalizeDNSMode(test.input)
		if err != nil {
			t.Fatal(err)
		}
		if output != test.output {
			t.Fatalf("unexpected DNS mode for %q: %q", test.input, output)
		}
	}
	if _, err := normalizeDNSMode("disabled"); err == nil {
		t.Fatal("expected an unknown DNS mode to be rejected")
	}
}

func TestNormalizeRedirectAddresses(t *testing.T) {
	tests := []struct {
		name      string
		addresses []netip.Prefix
		ipv4      string
		ipv6      string
	}{
		{
			name: "default",
			ipv4: "127.128.0.0/9",
		},
		{
			name:      "ipv4 only",
			addresses: []netip.Prefix{netip.MustParsePrefix("127.42.0.1/9")},
			ipv4:      "127.0.0.0/9",
		},
		{
			name:      "ipv6 only",
			addresses: []netip.Prefix{netip.MustParsePrefix("fd53:696e:672d:626f::1/64")},
			ipv6:      "fd53:696e:672d:626f::/64",
		},
		{
			name: "dual stack",
			addresses: []netip.Prefix{
				netip.MustParsePrefix("127.128.0.0/10"),
				netip.MustParsePrefix("fd53:696e:672d:626f::/64"),
			},
			ipv4: "127.128.0.0/10",
			ipv6: "fd53:696e:672d:626f::/64",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ipv4Prefix, ipv6Prefix, err := normalizeRedirectAddresses(test.addresses)
			if err != nil {
				t.Fatal(err)
			}
			if prefixString(ipv4Prefix) != test.ipv4 || prefixString(ipv6Prefix) != test.ipv6 {
				t.Fatalf("unexpected prefixes: IPv4=%v IPv6=%v", ipv4Prefix, ipv6Prefix)
			}
		})
	}
}

func TestNormalizeRedirectAddressesRejectsInvalid(t *testing.T) {
	tests := [][]netip.Prefix{
		{
			netip.MustParsePrefix("127.0.0.0/8"),
			netip.MustParsePrefix("10.0.0.0/8"),
		},
		{
			netip.MustParsePrefix("fd53:696e:672d:626f::/64"),
			netip.MustParsePrefix("fd00::/64"),
		},
		{netip.MustParsePrefix("127.0.0.0/7")},
		{netip.MustParsePrefix("127.0.0.0/11")},
		{netip.MustParsePrefix("10.0.0.0/8")},
		{netip.MustParsePrefix("1.0.0.0/8")},
		{netip.MustParsePrefix("2001:db8::/64")},
		{netip.MustParsePrefix("fe80::/64")},
		{netip.MustParsePrefix("fd53:696e:672d:626f::/96")},
		{netip.MustParsePrefix("0.0.0.0/8")},
		{netip.MustParsePrefix("ff00::/64")},
	}
	for _, addresses := range tests {
		if _, _, err := normalizeRedirectAddresses(addresses); err == nil {
			t.Fatalf("expected redirect addresses to be rejected: %v", addresses)
		}
	}
}

func TestLocalInterfacePrefixes(t *testing.T) {
	interfaces := []control.Interface{
		{
			Name: "lo",
			Addresses: []netip.Prefix{
				netip.MustParsePrefix("127.0.0.1/8"),
				netip.MustParsePrefix("::1/128"),
			},
		},
		{
			Name: "ap0",
			Addresses: []netip.Prefix{
				netip.MustParsePrefix("192.168.96.221/24"),
				netip.MustParsePrefix("fe80::1/64"),
				netip.MustParsePrefix("::ffff:192.168.97.1/120"),
			},
		},
	}
	prefixes := localInterfacePrefixes(interfaces)
	expected := []netip.Prefix{
		netip.MustParsePrefix("192.168.96.0/24"),
		netip.MustParsePrefix("fe80::/64"),
		netip.MustParsePrefix("192.168.97.0/24"),
	}
	if !slices.Equal(prefixes, expected) {
		t.Fatalf("unexpected local interface prefixes: %v", prefixes)
	}
}

func TestParseUIDRanges(t *testing.T) {
	ranges, err := parseUIDRanges([]uint32{0, 1000}, []string{"1001:99999", "0xffffffff:0xffffffff"})
	if err != nil {
		t.Fatal(err)
	}
	expected := [][2]uint32{{0, 0}, {1000, 1000}, {1001, 99999}, {0xffffffff, 0xffffffff}}
	if len(ranges) != len(expected) {
		t.Fatalf("unexpected UID range count: %d", len(ranges))
	}
	for rangeIndex, uidRange := range ranges {
		if uidRange.Start != expected[rangeIndex][0] || uidRange.End != expected[rangeIndex][1] {
			t.Fatalf("unexpected UID range %d: %+v", rangeIndex, uidRange)
		}
	}
}

func TestParseUIDRangesRejectsInvalid(t *testing.T) {
	for _, uidRange := range []string{"1000", ":1000", "1000:", "1001:1000", "x:1000"} {
		if _, err := parseUIDRanges(nil, []string{uidRange}); err == nil {
			t.Fatalf("expected UID range to be rejected: %s", uidRange)
		}
	}
}

func TestPlatformExcludedUIDRanges(t *testing.T) {
	if ranges := platformExcludedUIDRanges("linux"); len(ranges) != 0 {
		t.Fatalf("unexpected Linux platform exclusions: %+v", ranges)
	}
	ranges := platformExcludedUIDRanges("android")
	if len(ranges) != 1 || ranges[0].Start != androidTetheringDNSUID || ranges[0].End != androidTetheringDNSUID {
		t.Fatalf("unexpected Android platform exclusions: %+v", ranges)
	}
}

func TestRedirectAddressFromOOB(t *testing.T) {
	ipv4Address := netip.MustParseAddr("127.23.45.67")
	ipv4OOB := ipv4PacketInfo(ipv4Address)
	parsedIPv4, err := redirectAddressFromOOB(ipv4OOB)
	if err != nil {
		t.Fatal(err)
	}
	if parsedIPv4 != ipv4Address {
		t.Fatalf("unexpected IPv4 redirect address: %v", parsedIPv4)
	}

	ipv6Address := netip.MustParseAddr("fd53:696e:672d:626f::1234")
	ipv6OOB := ipv6PacketInfo(ipv6Address)
	parsedIPv6, err := redirectAddressFromOOB(ipv6OOB)
	if err != nil {
		t.Fatal(err)
	}
	if parsedIPv6 != ipv6Address {
		t.Fatalf("unexpected IPv6 redirect address: %v", parsedIPv6)
	}
}

func TestIPv6ListenerControlAllowsSharedPort(t *testing.T) {
	var listenConfig net.ListenConfig
	listenConfig.Control = (&Inbound{}).socketControl(true)
	listener6, err := listenConfig.Listen(context.Background(), "tcp", "[::]:0")
	if err != nil {
		t.Skipf("IPv6 TCP is unavailable: %v", err)
	}
	defer listener6.Close()
	tcpPort := listener6.Addr().(*net.TCPAddr).Port
	listener4, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4zero, Port: tcpPort})
	if err != nil {
		t.Fatalf("IPv6 TCP listener also occupied the IPv4 port: %v", err)
	}
	listener4.Close()

	packetConn6, err := listenConfig.ListenPacket(context.Background(), "udp", "[::]:0")
	if err != nil {
		t.Skipf("IPv6 UDP is unavailable: %v", err)
	}
	defer packetConn6.Close()
	udpPort := packetConn6.LocalAddr().(*net.UDPAddr).Port
	packetConn4, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: udpPort})
	if err != nil {
		t.Fatalf("IPv6 UDP listener also occupied the IPv4 port: %v", err)
	}
	packetConn4.Close()
}

func ipv4PacketInfo(address netip.Addr) []byte {
	oob := make([]byte, unix.CmsgSpace(unix.SizeofInet4Pktinfo))
	header := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))
	header.Level = unix.IPPROTO_IP
	header.Type = unix.IP_PKTINFO
	header.SetLen(unix.CmsgLen(unix.SizeofInet4Pktinfo))
	packetInfo := (*unix.Inet4Pktinfo)(unsafe.Pointer(&oob[unix.CmsgLen(0)]))
	packetInfo.Addr = address.As4()
	return oob
}

func ipv6PacketInfo(address netip.Addr) []byte {
	oob := make([]byte, unix.CmsgSpace(unix.SizeofInet6Pktinfo))
	header := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))
	header.Level = unix.IPPROTO_IPV6
	header.Type = unix.IPV6_PKTINFO
	header.SetLen(unix.CmsgLen(unix.SizeofInet6Pktinfo))
	packetInfo := (*unix.Inet6Pktinfo)(unsafe.Pointer(&oob[unix.CmsgLen(0)]))
	packetInfo.Addr = address.As16()
	return oob
}

func prefixString(prefix netip.Prefix) string {
	if !prefix.IsValid() {
		return ""
	}
	return prefix.String()
}
