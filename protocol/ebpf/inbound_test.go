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

	commonEBPF "github.com/sagernet/sing-box/common/ebpf"
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
			DisablePacketOutput: true,
			DisableLog:          true,
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

func TestValidateScopedOptions(t *testing.T) {
	if err := validateLocalOptions(false, option.EBPFLocalOptions{}); err != nil {
		t.Fatal(err)
	}
	for _, options := range []option.EBPFLocalOptions{
		{IPv6: common.Ptr(false)},
		{BypassPrivateAddress: common.Ptr(false)},
		{IncludeUID: []uint32{1000}},
		{IncludeUIDRange: []string{"1000:2000"}},
		{ExcludeUID: []uint32{1000}},
		{ExcludeUIDRange: []string{"1000:2000"}},
		{IncludeAndroidUser: []int{0}},
		{IncludePackage: []string{"com.example.include"}},
		{ExcludePackage: []string{"com.example.exclude"}},
		{BypassPort: []uint16{443}},
		{BypassPortRange: []string{"8000:8080"}},
	} {
		if err := validateLocalOptions(false, options); err == nil {
			t.Fatalf("expected local-only options to be rejected: %+v", options)
		}
	}
	if err := validateSharedOptions(false, option.EBPFSharedOptions{Interface: []string{"ap0"}}); err == nil {
		t.Fatal("expected shared-only options to be rejected")
	}
	if err := validateLocalOptions(false, option.EBPFLocalOptions{DataPlane: localDataPlaneCgroup}); err == nil {
		t.Fatal("expected a local data plane to be rejected when local interception is disabled")
	}
	if err := validateSharedOptions(false, option.EBPFSharedOptions{DataPlane: sharedDataPlanePacketRewrite}); err == nil {
		t.Fatal("expected a shared data plane to be rejected when shared interception is disabled")
	}
	if err := validateSharedOptions(false, option.EBPFSharedOptions{IPv6: common.Ptr(false)}); err == nil {
		t.Fatal("expected shared IPv6 option to be rejected without shared mode")
	}
	if err := validateSharedOptions(false, option.EBPFSharedOptions{BypassPrivateAddress: common.Ptr(false)}); err == nil {
		t.Fatal("expected shared private-address policy to be rejected without shared mode")
	}
}

func TestNormalizeLocalDataPlane(t *testing.T) {
	for _, testCase := range []struct {
		name       string
		options    option.EBPFLocalOptions
		dataPlane  string
		cgroupPath string
	}{
		{name: "default", options: option.EBPFLocalOptions{}, dataPlane: localDataPlaneCgroup},
		{name: "explicit tc", options: option.EBPFLocalOptions{DataPlane: "tc"}, dataPlane: localDataPlaneTC},
		{name: "cgroup root", options: option.EBPFLocalOptions{DataPlane: "cgroup"}, dataPlane: localDataPlaneCgroup},
		{name: "explicit cgroup", options: option.EBPFLocalOptions{DataPlane: "cgroup", CgroupPath: "/sys/fs/cgroup/sing-box"}, dataPlane: localDataPlaneCgroup, cgroupPath: "/sys/fs/cgroup/sing-box"},
		{name: "implicit cgroup path", options: option.EBPFLocalOptions{CgroupPath: "/sys/fs/cgroup/sing-box"}, dataPlane: localDataPlaneCgroup, cgroupPath: "/sys/fs/cgroup/sing-box"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			dataPlane, path, err := normalizeLocalDataPlane(testCase.options)
			if err != nil {
				t.Fatal(err)
			}
			if dataPlane != testCase.dataPlane || path != testCase.cgroupPath {
				t.Fatalf("got data_plane=%q path=%q", dataPlane, path)
			}
		})
	}
	for _, options := range []option.EBPFLocalOptions{
		{DataPlane: "invalid"},
		{DataPlane: "tc", CgroupPath: "/sys/fs/cgroup/sing-box"},
		{DataPlane: "cgroup", CgroupPath: "relative"},
	} {
		if _, _, err := normalizeLocalDataPlane(options); err == nil {
			t.Fatalf("expected invalid local data plane options to fail: %+v", options)
		}
	}
}

func TestEnabledByDefault(t *testing.T) {
	if !enabledByDefault(nil) || !enabledByDefault(common.Ptr(true)) || enabledByDefault(common.Ptr(false)) {
		t.Fatal("unexpected default-enabled boolean behavior")
	}
}

func TestParsePortRanges(t *testing.T) {
	ranges, err := parsePortRanges("local.bypass_port", []uint16{443, 80}, []string{"8000:8002", "81:82", "82:83"})
	if err != nil {
		t.Fatal(err)
	}
	want := []commonEBPF.PortRange{{Start: 80, End: 83}, {Start: 443, End: 443}, {Start: 8000, End: 8002}}
	if !slices.Equal(ranges, want) {
		t.Fatalf("unexpected port ranges: got %v, want %v", ranges, want)
	}
	for _, invalid := range []string{"0:1", "2:1", "1", "1:65536"} {
		if _, err = parsePortRanges("local.bypass_port", nil, []string{invalid}); err == nil {
			t.Fatalf("expected invalid port range %q to fail", invalid)
		}
	}
}

func TestNormalizeEnablement(t *testing.T) {
	tests := []struct {
		name         string
		localOption  *bool
		sharedOption *bool
		local        bool
		shared       bool
		wantErr      bool
	}{
		{name: "default", local: true},
		{name: "local", localOption: common.Ptr(true), local: true},
		{name: "shared", sharedOption: common.Ptr(true), shared: true},
		{name: "hybrid", localOption: common.Ptr(true), sharedOption: common.Ptr(true), local: true, shared: true},
		{name: "disabled local", localOption: common.Ptr(false), wantErr: true},
		{name: "disabled shared", sharedOption: common.Ptr(false), wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			local, shared, err := normalizeEnablement(test.localOption, test.sharedOption)
			if test.wantErr {
				if err == nil {
					t.Fatal("expected invalid enablement to be rejected")
				}
				return
			}
			if err != nil || local != test.local || shared != test.shared {
				t.Fatalf("unexpected normalized enablement: local=%v shared=%v err=%v", local, shared, err)
			}
		})
	}
}

func TestNormalizeSharedDataPlane(t *testing.T) {
	for _, test := range []struct {
		input  string
		output string
	}{
		{"", sharedDataPlanePacketRewrite},
		{sharedDataPlaneSocketAssign, sharedDataPlaneSocketAssign},
		{sharedDataPlanePacketRewrite, sharedDataPlanePacketRewrite},
	} {
		output, err := normalizeSharedDataPlane(option.EBPFSharedOptions{DataPlane: test.input})
		if err != nil {
			t.Fatal(err)
		}
		if output != test.output {
			t.Fatalf("unexpected shared data plane for %q: %q", test.input, output)
		}
	}
	if _, err := normalizeSharedDataPlane(option.EBPFSharedOptions{DataPlane: "invalid"}); err == nil {
		t.Fatal("expected unknown shared data plane to be rejected")
	}
}

func TestParseSharedMACAddresses(t *testing.T) {
	addresses, err := parseSharedMACAddresses("include_mac_address", []string{
		"02:00:00:00:00:01",
		"02-00-00-00-00-01",
		"02:00:00:00:00:02",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(addresses) != 2 || addresses[0] != (commonEBPF.MACAddress{0x02, 0, 0, 0, 0, 1}) ||
		addresses[1] != (commonEBPF.MACAddress{0x02, 0, 0, 0, 0, 2}) {
		t.Fatalf("unexpected parsed MAC addresses: %v", addresses)
	}
	for _, address := range []string{"invalid", "02:00:00:00:00:00:00:01"} {
		if _, err = parseSharedMACAddresses("include_mac_address", []string{address}); err == nil {
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

func TestCollectHostAddresses(t *testing.T) {
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
				netip.MustParsePrefix("fe80::1/64"),
				netip.MustParsePrefix("192.168.96.221/24"),
				netip.MustParsePrefix("fe80::1/64"),
				netip.MustParsePrefix("::ffff:192.168.97.1/120"),
			},
		},
	}
	addresses := collectHostAddresses(interfaces)
	expected := []netip.Addr{
		netip.MustParseAddr("192.168.96.221"),
		netip.MustParseAddr("192.168.97.1"),
		netip.MustParseAddr("fe80::1"),
	}
	if !slices.Equal(addresses, expected) {
		t.Fatalf("unexpected host addresses: %v", addresses)
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
