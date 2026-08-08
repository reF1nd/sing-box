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

	ECommon "github.com/sagernet/sing-box/common/ebpf"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/common/json/badoption"

	"golang.org/x/sys/unix"
)

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

func TestInternalListenerSetsSelectIndependentPorts(t *testing.T) {
	newListener := func(network string, _ bool, port uint16) *listener.Listener {
		return listener.New(listener.Options{
			Context: context.Background(),
			Logger:  log.NewNOPFactory().Logger(),
			Network: []string{network},
			Listen: option.ListenOptions{
				Listen:     common.Ptr(badoption.Addr(netip.IPv4Unspecified())),
				ListenPort: port,
			},
			DisablePacketOutput:  true,
			DisableConnectionLog: true,
		})
	}
	var first internalListenerSet
	if err := first.start(true, true, true, false, newListener); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = first.close() })
	if first.selectedPort() == 0 {
		t.Fatal("first listener set did not select a port")
	}
	if tcpPort := uint16(first.tcp4.TCPListener().Addr().(*net.TCPAddr).Port); tcpPort != first.selectedPort() {
		t.Fatalf("unexpected TCP listener port: %d != %d", tcpPort, first.selectedPort())
	}
	if udpPort := uint16(first.udp4.UDPConn().LocalAddr().(*net.UDPAddr).Port); udpPort != first.selectedPort() {
		t.Fatalf("unexpected UDP listener port: %d != %d", udpPort, first.selectedPort())
	}

	var second internalListenerSet
	if err := second.start(true, true, true, false, newListener); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = second.close() })
	if second.selectedPort() == 0 || second.selectedPort() == first.selectedPort() {
		t.Fatalf("listener sets did not select independent ports: first=%d second=%d", first.selectedPort(), second.selectedPort())
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

func TestValidateCgroupOptions(t *testing.T) {
	if err := validateCgroupOptions(false, option.EBPFInboundOptions{}); err != nil {
		t.Fatal(err)
	}
	mapCapacity := option.EBPFMapCapacity(1024)
	for _, options := range []option.EBPFInboundOptions{
		{CgroupPath: "/sys/fs/cgroup"},
		{CgroupIPv6Mode: cgroupIPv6ModeAuto},
		{IncludeUID: []uint32{1000}},
		{IncludeUIDRange: []string{"1000:2000"}},
		{ExcludeUID: []uint32{1000}},
		{ExcludeUIDRange: []string{"1000:2000"}},
		{IncludeAndroidUser: []int{0}},
		{IncludePackage: []string{"com.example.include"}},
		{ExcludePackage: []string{"com.example.exclude"}},
		{MapCapacity: option.EBPFMapCapacityOptions{TCPRedirect: &mapCapacity}},
	} {
		if err := validateCgroupOptions(false, options); err == nil {
			t.Fatalf("expected cgroup-only options to be rejected: %+v", options)
		}
	}
	if err := validateCgroupOptions(true, option.EBPFInboundOptions{
		CgroupPath: "/sys/fs/cgroup",
		IncludeUID: []uint32{1000},
	}); err != nil {
		t.Fatal(err)
	}
}

func TestNormalizeCgroupIPv6Mode(t *testing.T) {
	for _, test := range []struct {
		input  string
		output string
	}{
		{"", cgroupIPv6ModeAlways},
		{cgroupIPv6ModeAlways, cgroupIPv6ModeAlways},
		{cgroupIPv6ModeAuto, cgroupIPv6ModeAuto},
		{cgroupIPv6ModeOff, cgroupIPv6ModeOff},
	} {
		output, err := normalizeCgroupIPv6Mode(test.input)
		if err != nil {
			t.Fatal(err)
		}
		if output != test.output {
			t.Fatalf("unexpected cgroup IPv6 mode for %q: %q", test.input, output)
		}
	}
	if _, err := normalizeCgroupIPv6Mode("prefer"); err == nil {
		t.Fatal("expected an unknown cgroup IPv6 mode to be rejected")
	}
}

func TestValidateCgroupAddressFamilies(t *testing.T) {
	ipv4 := netip.MustParsePrefix("127.128.0.0/9")
	ipv6 := netip.MustParsePrefix("fd53:696e:672d:626f::/64")
	for _, test := range []struct {
		mode string
		ipv4 netip.Prefix
		ipv6 netip.Prefix
	}{
		{cgroupIPv6ModeAlways, ipv4, netip.Prefix{}},
		{cgroupIPv6ModeOff, ipv4, ipv6},
		{cgroupIPv6ModeAlways, netip.Prefix{}, ipv6},
		{cgroupIPv6ModeAuto, netip.Prefix{}, ipv6},
	} {
		if err := validateCgroupAddressFamilies(true, test.mode, test.ipv4, test.ipv6); err != nil {
			t.Fatal(err)
		}
	}
	for _, mode := range []string{cgroupIPv6ModeAlways, cgroupIPv6ModeAuto, cgroupIPv6ModeOff} {
		if err := validateCgroupAddressFamilies(true, mode, netip.Prefix{}, netip.Prefix{}); err == nil {
			t.Fatalf("expected empty address families to be rejected for %s", mode)
		}
	}
	if err := validateCgroupAddressFamilies(
		true,
		cgroupIPv6ModeOff,
		netip.Prefix{},
		ipv6,
	); err == nil {
		t.Fatal("expected IPv6-only cgroup with IPv6 disabled to be rejected")
	}
}

func TestUsableNativeIPv6(t *testing.T) {
	for _, address := range []string{"2001:db8::1", "fd00::1"} {
		if !usableNativeIPv6(net.ParseIP(address)) {
			t.Fatalf("expected %s to be usable", address)
		}
	}
	for _, address := range []string{"", "127.0.0.1", "::", "::1", "fe80::1", "ff02::1"} {
		if usableNativeIPv6(net.ParseIP(address)) {
			t.Fatalf("expected %q to be unusable", address)
		}
	}
}

func TestValidateDataPaths(t *testing.T) {
	if err := validateDataPaths(false, false); err == nil {
		t.Fatal("expected an inbound without a data path to be rejected")
	}
	if err := validateDataPaths(true, false); err != nil {
		t.Fatal(err)
	}
	if err := validateDataPaths(false, true); err != nil {
		t.Fatal(err)
	}
}

func TestDisabledSharedNetworkIgnoresSubOptions(t *testing.T) {
	zeroCapacity := option.EBPFMapCapacity(0)
	normalized, err := normalizeSharedNetworkOptions(option.EBPFSharedNetworkOptions{
		IncludeInterface:  []string{""},
		IncludeSourceCIDR: []netip.Prefix{{}},
		ExcludeSourceCIDR: []netip.Prefix{{}},
		IncludeMACAddress: []string{"invalid"},
		ExcludeMACAddress: []string{"invalid"},
		TCPriority:        option.EBPFTCPriority(42),
		MapCapacity: option.EBPFSharedNetworkMapCapacityOptions{
			Proxy: &zeroCapacity,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if normalized.Enabled || len(normalized.IncludeInterface) != 0 ||
		len(normalized.IncludeSourceCIDR) != 0 || len(normalized.ExcludeSourceCIDR) != 0 ||
		len(normalized.IncludeMACAddress) != 0 || len(normalized.ExcludeMACAddress) != 0 ||
		normalized.TCPriority != 0 || normalized.MapCapacity != (option.EBPFSharedNetworkMapCapacityOptions{}) {
		t.Fatalf("disabled shared-network options were not ignored: %+v", normalized)
	}
	capacity, err := normalizeSharedNetworkMapCapacity(normalized.MapCapacity)
	if err != nil {
		t.Fatal(err)
	}
	if capacity != ECommon.DefaultSharedNetworkMapCapacities() {
		t.Fatalf("unexpected disabled shared-network map capacity: %+v", capacity)
	}
}

func TestParseSharedNetworkMACAddresses(t *testing.T) {
	addresses, err := parseSharedNetworkMACAddresses("include_mac_address", []string{
		"02:00:00:00:00:01",
		"02-00-00-00-00-01",
		"02:00:00:00:00:02",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(addresses) != 2 || addresses[0] != (ECommon.MACAddress{0x02, 0, 0, 0, 0, 1}) ||
		addresses[1] != (ECommon.MACAddress{0x02, 0, 0, 0, 0, 2}) {
		t.Fatalf("unexpected parsed MAC addresses: %v", addresses)
	}
	for _, address := range []string{"invalid", "02:00:00:00:00:00:00:01"} {
		if _, err = parseSharedNetworkMACAddresses("include_mac_address", []string{address}); err == nil {
			t.Fatalf("expected MAC address to be rejected: %s", address)
		}
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

func TestNormalizeMapCapacity(t *testing.T) {
	capacity, err := normalizeCgroupMapCapacity(option.EBPFMapCapacityOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if capacity != ECommon.DefaultCgroupMapCapacity() {
		t.Fatalf("unexpected default map capacity: %+v", capacity)
	}
	tcpCapacity := option.EBPFMapCapacity(32768)
	udpCapacity := option.EBPFMapCapacity(131072)
	socketCapacity := option.EBPFMapCapacity(16384)
	capacity, err = normalizeCgroupMapCapacity(option.EBPFMapCapacityOptions{
		TCPRedirect:  &tcpCapacity,
		UDPRedirect:  &udpCapacity,
		SocketBypass: &socketCapacity,
	})
	if err != nil {
		t.Fatal(err)
	}
	if capacity.TCPRedirect != uint32(tcpCapacity) ||
		capacity.UDPRedirect != uint32(udpCapacity) ||
		capacity.SocketBypass != uint32(socketCapacity) {
		t.Fatalf("unexpected custom map capacity: %+v", capacity)
	}
}

func TestNormalizeSharedNetworkMapCapacity(t *testing.T) {
	capacity, err := normalizeSharedNetworkMapCapacity(option.EBPFSharedNetworkMapCapacityOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if capacity != ECommon.DefaultSharedNetworkMapCapacities() {
		t.Fatalf("unexpected default shared-network map capacity: %+v", capacity)
	}
	proxy := option.EBPFMapCapacity(32768)
	bypass := option.EBPFMapCapacity(8192)
	fragment := option.EBPFMapCapacity(131072)
	capacity, err = normalizeSharedNetworkMapCapacity(option.EBPFSharedNetworkMapCapacityOptions{
		Proxy:    &proxy,
		Bypass:   &bypass,
		Fragment: &fragment,
	})
	if err != nil {
		t.Fatal(err)
	}
	if capacity.Proxy != uint32(proxy) || capacity.Bypass != uint32(bypass) ||
		capacity.Fragment != uint32(fragment) {
		t.Fatalf("unexpected shared-network map capacity: %+v", capacity)
	}
}

func TestNormalizeMapCapacityRejectsExplicitInvalidValues(t *testing.T) {
	zero := option.EBPFMapCapacity(0)
	tooLarge := option.EBPFMapCapacity(ECommon.MaxConfigurableMapCapacity + 1)
	for _, configured := range []*option.EBPFMapCapacity{&zero, &tooLarge} {
		if _, err := normalizeCgroupMapCapacity(option.EBPFMapCapacityOptions{
			UDPRedirect: configured,
		}); err == nil {
			t.Fatalf("expected map capacity %d to be rejected", *configured)
		}
		if _, err := normalizeSharedNetworkMapCapacity(option.EBPFSharedNetworkMapCapacityOptions{
			Proxy: configured,
		}); err == nil {
			t.Fatalf("expected shared-network map capacity %d to be rejected", *configured)
		}
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

func TestRedirectAddressFromOOBAllocations(t *testing.T) {
	oob := ipv4PacketInfo(netip.MustParseAddr("127.23.45.67"))
	allocations := testing.AllocsPerRun(1000, func() {
		if _, err := redirectAddressFromOOB(oob); err != nil {
			t.Fatal(err)
		}
	})
	if allocations != 0 {
		t.Fatalf("unexpected packet info parsing allocations: %v", allocations)
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
