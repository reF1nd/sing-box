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

func TestRedirectListenerDestination(t *testing.T) {
	inbound := &Inbound{
		redirectIPv4Prefix: netip.MustParsePrefix("127.128.0.0/9"),
		redirectIPv6Prefix: netip.MustParsePrefix("fd53:696e:672d:626f::/64"),
	}
	const listenerPort = 12345
	for _, test := range []struct {
		name        string
		destination string
		match       bool
	}{
		{"IPv4 token", "127.128.0.1:12345", true},
		{"IPv4-mapped token", "[::ffff:127.128.0.1]:12345", true},
		{"IPv6 token", "[fd53:696e:672d:626f::1]:12345", true},
		{"wrong port", "127.128.0.1:12346", false},
		{"public address", "1.1.1.1:12345", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if matched := inbound.isRedirectListenerDestination(
				netip.MustParseAddrPort(test.destination),
				listenerPort,
			); matched != test.match {
				t.Fatalf("unexpected match result: %v", matched)
			}
		})
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

func TestValidateScopedOptions(t *testing.T) {
	if err := validateLocalOptions(false, option.EBPFLocalOptions{}); err != nil {
		t.Fatal(err)
	}
	for _, options := range []option.EBPFLocalOptions{
		{CgroupPath: "/sys/fs/cgroup"},
		{IPv6: common.Ptr(false)},
		{BypassPrivateAddress: common.Ptr(false)},
		{IncludeUID: []uint32{1000}},
		{IncludeUIDRange: []string{"1000:2000"}},
		{ExcludeUID: []uint32{1000}},
		{ExcludeUIDRange: []string{"1000:2000"}},
		{IncludeAndroidUser: []int{0}},
		{IncludePackage: []string{"com.example.include"}},
		{ExcludePackage: []string{"com.example.exclude"}},
	} {
		if err := validateLocalOptions(false, options); err == nil {
			t.Fatalf("expected local-only options to be rejected: %+v", options)
		}
	}
	if err := validateSharedOptions(false, option.EBPFSharedOptions{Interface: []string{"ap0"}}); err == nil {
		t.Fatal("expected shared-only options to be rejected")
	}
	if err := validateSharedOptions(false, option.EBPFSharedOptions{IPv6: common.Ptr(false)}); err == nil {
		t.Fatal("expected shared IPv6 option to be rejected without shared mode")
	}
	if err := validateSharedOptions(false, option.EBPFSharedOptions{BypassPrivateAddress: common.Ptr(false)}); err == nil {
		t.Fatal("expected shared private-address policy to be rejected without shared mode")
	}
}

func TestRequiresIPv6Redirect(t *testing.T) {
	tests := []struct {
		name       string
		inbound    Inbound
		required   bool
		sharedOnly bool
	}{
		{
			name:     "local enabled",
			inbound:  Inbound{cgroupEnabled: true, localIPv6: true},
			required: true,
		},
		{
			name:    "local disabled",
			inbound: Inbound{cgroupEnabled: true},
		},
		{
			name:       "shared enabled",
			inbound:    Inbound{sharedNetworkEnabled: true, sharedIPv6: true},
			required:   true,
			sharedOnly: true,
		},
		{
			name:    "shared disabled",
			inbound: Inbound{sharedNetworkEnabled: true},
		},
		{
			name: "hybrid local enabled shared disabled",
			inbound: Inbound{
				cgroupEnabled: true, localIPv6: true,
				sharedNetworkEnabled: true,
			},
			required: true,
		},
		{
			name: "hybrid local disabled shared enabled",
			inbound: Inbound{
				cgroupEnabled:        true,
				sharedNetworkEnabled: true, sharedIPv6: true,
			},
			required:   true,
			sharedOnly: true,
		},
	}
	for index := range tests {
		test := &tests[index]
		t.Run(test.name, func(t *testing.T) {
			if required := test.inbound.requiresIPv6Redirect(); required != test.required {
				t.Fatalf("unexpected IPv6 redirect requirement: %v", required)
			}
			test.inbound.redirectIPv6Prefix = redirectIPv6Candidates[0]
			if enabled := test.inbound.sharedNetworkIPv6Enabled(); enabled != test.sharedOnly {
				t.Fatalf("unexpected shared IPv6 state: %v", enabled)
			}
			prefix := test.inbound.sharedRedirectIPv6Prefix()
			if prefix.IsValid() != test.sharedOnly {
				t.Fatalf("unexpected shared IPv6 redirect prefix: %v", prefix)
			}
		})
	}
}

func TestNormalizeMode(t *testing.T) {
	for _, test := range []struct {
		input  string
		mode   string
		local  bool
		shared bool
	}{
		{"", ebpfModeLocal, true, false},
		{ebpfModeLocal, ebpfModeLocal, true, false},
		{ebpfModeShared, ebpfModeShared, false, true},
		{ebpfModeHybrid, ebpfModeHybrid, true, true},
	} {
		mode, local, shared, err := normalizeMode(test.input)
		if err != nil {
			t.Fatal(err)
		}
		if mode != test.mode || local != test.local || shared != test.shared {
			t.Fatalf("unexpected normalized mode for %q: %q %v %v", test.input, mode, local, shared)
		}
	}
	if _, _, _, err := normalizeMode("disabled"); err == nil {
		t.Fatal("expected an unknown mode to be rejected")
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
		{"", dnsModeRespectPolicy},
		{dnsModeHijack, dnsModeHijack},
		{dnsModeRespectPolicy, dnsModeRespectPolicy},
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
	for _, mode := range []string{"disabled", "respect_bypass", "respect_bypass_hijack"} {
		if _, err := normalizeDNSMode(mode); err == nil {
			t.Fatalf("expected unknown DNS mode %q to be rejected", mode)
		}
	}
}

func TestEffectiveSharedNetworkMapCapacity(t *testing.T) {
	capacity := ECommon.DefaultSharedNetworkMapCapacities()
	optimized := effectiveSharedNetworkMapCapacity(capacity, false)
	if optimized.Proxy != capacity.Proxy || optimized.Bypass != 1 {
		t.Fatalf("unexpected optimized shared-network map capacity: %+v", optimized)
	}
	configured := effectiveSharedNetworkMapCapacity(capacity, true)
	if configured != capacity {
		t.Fatalf("unexpected configured shared-network map capacity: %+v", configured)
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
		netip.MustParsePrefix("192.168.96.221/32"),
		netip.MustParsePrefix("fe80::1/128"),
		netip.MustParsePrefix("192.168.97.1/32"),
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
