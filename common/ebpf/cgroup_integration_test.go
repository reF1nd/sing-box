//go:build with_ebpf && (linux || android) && cgo && ebpf_integration

package ebpf

import (
	"bytes"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
)

const (
	integrationTestEnv          = "SING_BOX_EBPF_INTEGRATION"
	integrationTrafficHelperEnv = "SING_BOX_EBPF_TRAFFIC_HELPER"
	integrationTGIDHelperEnv    = "SING_BOX_EBPF_TGID_HELPER"
)

func TestCgroupBackendProgramLoadIntegration(t *testing.T) {
	requireEBPFIntegration(t, "load eBPF programs")
	addressFamilies := []struct {
		name       string
		enableIPv6 bool
		autoIPv6   bool
	}{
		{name: "ipv4"},
		{name: "dual_stack", enableIPv6: true},
		{name: "dual_stack_auto", enableIPv6: true, autoIPv6: true},
	}
	protocols := []struct {
		name      string
		enableTCP bool
		enableUDP bool
	}{
		{name: "tcp", enableTCP: true},
		{name: "udp", enableUDP: true},
		{name: "tcp_udp", enableTCP: true, enableUDP: true},
	}
	for _, addressFamily := range addressFamilies {
		for _, protocol := range protocols {
			for _, hijackDNS := range []bool{true, false} {
				dnsMode := "off"
				if hijackDNS {
					dnsMode = "hijack"
				}
				for _, selfTGID := range []uint32{uint32(os.Getpid()), 0} {
					selfBypass := "tgid"
					if selfTGID == 0 {
						selfBypass = "socket_cookie"
					}
					name := addressFamily.name + "/" + protocol.name + "/" + dnsMode + "/" + selfBypass
					t.Run(name, func(t *testing.T) {
						testCgroupBackendProgramLoad(t, cgroupProgramLoadOptions{
							enableTCP:          protocol.enableTCP,
							enableUDP:          protocol.enableUDP,
							enableIPv6:         addressFamily.enableIPv6,
							autoIPv6:           addressFamily.autoIPv6,
							hijackDNS:          hijackDNS,
							selfTGID:           selfTGID,
							expectedSelfBypass: selfBypass,
						})
					})
				}
			}
		}
	}
}

type cgroupProgramLoadOptions struct {
	enableTCP          bool
	enableUDP          bool
	enableIPv6         bool
	autoIPv6           bool
	hijackDNS          bool
	selfTGID           uint32
	expectedSelfBypass string
}

func testCgroupBackendProgramLoad(t *testing.T, options cgroupProgramLoadOptions) {
	backend, err := PrepareCgroup(CgroupConfig{
		Path:          os.Getenv("SING_BOX_EBPF_INTEGRATION_CGROUP"),
		EnableTCP:     options.enableTCP,
		EnableUDP:     options.enableUDP,
		EnableIPv6:    options.enableIPv6,
		AutoIPv6:      options.autoIPv6,
		IPv6Available: true,
		RedirectIPv4:  netip.MustParsePrefix("127.128.0.0/9"),
		RedirectIPv6:  netip.MustParsePrefix("fd53:696e:672d:626f::/64"),
		MapCapacity:   DefaultCgroupMapCapacity(),
		UDPTimeout:    5 * time.Minute,
		Policy:        CgroupPolicy{HijackDNS: options.hijackDNS},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := backend.Close(); err != nil {
			t.Errorf("close eBPF backend: %v", err)
		}
	})
	pendingSocket := prepareProtectedIntegrationSocket(t, backend, "udp4", unix.SOCK_DGRAM, unix.IPPROTO_UDP)
	defer pendingSocket.Close()
	pendingCookie, err := readSocketCookie(pendingSocket.Fd())
	if err != nil {
		t.Fatal(err)
	}
	if _, loaded := backend.pendingSocketCookies[pendingCookie]; !loaded {
		t.Fatal("socket protected before program load was not queued")
	}
	if err = backend.loadPrograms(65532, options.selfTGID); err != nil {
		t.Fatal(err)
	}
	if len(backend.pendingSocketCookies) != 0 {
		t.Fatal("pending socket cookies were not released after program load")
	}
	if options.autoIPv6 {
		if changed, updateErr := backend.UpdateIPv6Available(false); updateErr != nil || !changed {
			t.Fatalf("disable automatic IPv6 interception: changed=%v err=%v", changed, updateErr)
		}
		if changed, updateErr := backend.UpdateIPv6Available(true); updateErr != nil || !changed {
			t.Fatalf("enable automatic IPv6 interception: changed=%v err=%v", changed, updateErr)
		}
	}
	actualSelfBypass := backend.SelfBypassMode()
	if options.expectedSelfBypass == "socket_cookie" && actualSelfBypass != options.expectedSelfBypass {
		t.Fatalf("unexpected self bypass mode: %s", actualSelfBypass)
	}
	if options.expectedSelfBypass == "tgid" && actualSelfBypass == "socket_cookie" {
		t.Log("kernel rejected TGID self bypass; socket-cookie fallback loaded successfully")
	} else if actualSelfBypass != options.expectedSelfBypass {
		t.Fatalf("unexpected self bypass mode: %s", actualSelfBypass)
	}
	if actualSelfBypass == "tgid" {
		if backend.socketBypassMapFD >= 0 {
			t.Fatal("TGID self bypass unexpectedly created a socket-cookie map")
		}
		if err = backend.SocketProtectFunc()("tcp", "", nil); err != nil {
			t.Fatalf("TGID socket protector did not return directly: %v", err)
		}
	} else if backend.socketBypassMapFD < 0 {
		t.Fatal("socket-cookie fallback did not create its bypass map")
	} else {
		var value uint8
		if err = lookupMap(
			backend.socketBypassMapFD,
			unsafe.Pointer(&pendingCookie),
			unsafe.Pointer(&value),
		); err != nil {
			t.Fatalf("pending socket cookie was not registered: %v", err)
		}
		if value != 1 {
			t.Fatalf("unexpected pending socket cookie value: %d", value)
		}
	}

	programs := backend.AttachedPrograms()
	if len(programs) == 0 {
		t.Fatal("no cgroup program was built")
	}
	if options.enableUDP && backend.UsesSocketRelease() && !containsProgram(programs, "sb_ebpf_rel (cgroup/sock_release)") {
		t.Fatalf("socket-release program was not reported: %v", programs)
	}
	if options.enableUDP && !backend.UsesSocketRelease() {
		t.Log("kernel does not support cgroup/sock_release; UDP LRU fallback loaded successfully")
	}
	if os.Getenv("SING_BOX_EBPF_INTEGRATION_ATTACH") == "1" {
		if err = backend.Attach(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSharedNetworkSharedMapProgramLoadIntegration(t *testing.T) {
	requireEBPFIntegration(t, "load shared-network programs with cgroup policy maps")
	backend, err := PrepareCgroup(CgroupConfig{
		Path:         os.Getenv("SING_BOX_EBPF_INTEGRATION_CGROUP"),
		EnableTCP:    true,
		EnableUDP:    true,
		RedirectIPv4: netip.MustParsePrefix("127.128.0.0/9"),
		RedirectIPv6: netip.MustParsePrefix("fd53:696e:672d:626f::/64"),
		MapCapacity:  DefaultCgroupMapCapacity(),
		UDPTimeout:   5 * time.Minute,
		Policy:       CgroupPolicy{EnableBypassCIDR: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := backend.Close(); err != nil {
			t.Errorf("close eBPF backend: %v", err)
		}
	})
	for _, hijackDNS := range []bool{true, false} {
		dnsMode := "off"
		if hijackDNS {
			dnsMode = "hijack"
		}
		t.Run(dnsMode, func(t *testing.T) {
			prepareSharedNetworkProgramLoad(t, backend, hijackDNS)
		})
	}
}

func prepareSharedNetworkProgramLoad(t *testing.T, cgroupBackend *CgroupBackend, hijackDNS bool) *SharedNetworkBackend {
	t.Helper()
	sharedBackend, err := PrepareSharedNetwork(cgroupBackend, SharedNetworkConfig{
		ListenerPort: 65531,
		EnableTCP:    true,
		EnableUDP:    true,
		HijackDNS:    hijackDNS,
		RedirectIPv4: netip.MustParsePrefix("127.128.0.0/9"),
		RedirectIPv6: netip.MustParsePrefix("fd53:696e:672d:626f::/64"),
		MapCapacity:  SharedNetworkMapCapacity,
		UDPTimeout:   5 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := sharedBackend.Close(); err != nil {
			t.Errorf("close shared-network token backend: %v", err)
		}
	})
	if sharedBackend.IngressProgramFD() < 0 || sharedBackend.EgressProgramFD() < 0 {
		t.Fatal("shared-network token programs were not loaded")
	}
	if hasDNSHijack := sharedBackend.control.Flags&sharedNetworkFlagDNSHijack != 0; hasDNSHijack != hijackDNS {
		t.Fatalf("unexpected shared-network DNS hijack flag: %t", hasDNSHijack)
	}
	if err = sharedBackend.UpdateHostAddresses([]netip.Addr{
		netip.MustParseAddr("192.0.2.1"),
		netip.MustParseAddr("2001:db8::1"),
	}); err != nil {
		t.Fatal(err)
	}
	if err = sharedBackend.Enable(); err != nil {
		t.Fatal(err)
	}
	if sharedBackend.control.Enabled != 1 {
		t.Fatal("shared-network backend was not enabled")
	}
	if err = sharedBackend.UpdateHostAddresses([]netip.Addr{
		netip.MustParseAddr("192.0.2.2"),
		netip.MustParseAddr("2001:db8::2"),
	}); err != nil {
		t.Fatal(err)
	}
	if sharedBackend.control.Enabled != 1 {
		t.Fatal("shared-network host policy update disabled the data path")
	}
	if cgroupBackend == nil {
		if _, err = sharedBackend.UpdateBypassCIDR([]netip.Prefix{
			netip.MustParsePrefix("198.51.100.0/24"),
		}); err != nil {
			t.Fatal(err)
		}
	} else if err = sharedBackend.SetBypassCIDRState([]netip.Prefix{
		netip.MustParsePrefix("198.51.100.0/24"),
	}); err != nil {
		t.Fatal(err)
	}
	if sharedBackend.control.Flags&sharedNetworkFlagBypassIPv4 == 0 {
		t.Fatal("shared-network IPv4 bypass policy is disabled")
	}
	if err = sharedBackend.UpdateHostAddresses([]netip.Addr{
		netip.MustParseAddr("192.0.2.3"),
		netip.MustParseAddr("2001:db8::3"),
	}); err != nil {
		t.Fatal(err)
	}
	if sharedBackend.control.Flags&sharedNetworkFlagBypassIPv4 == 0 {
		t.Fatal("shared-network host policy update disabled the IPv4 bypass policy")
	}
	if sharedBackend.control.Enabled != 1 {
		t.Fatal("shared-network bypass policy update disabled the data path")
	}
	if err = sharedBackend.Disable(); err != nil {
		t.Fatal(err)
	}
	if sharedBackend.control.Enabled != 0 {
		t.Fatal("shared-network backend was not disabled")
	}
	return sharedBackend
}

func TestCgroupBackendTrafficIntegration(t *testing.T) {
	requireEBPFIntegration(t, "test redirected traffic")
	cgroupMount, err := DetectCgroup2Mount()
	if err != nil {
		t.Fatal(err)
	}
	cgroupPath, err := os.MkdirTemp(cgroupMount, "sing-box-ebpf-integration-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err = os.Remove(cgroupPath); err != nil {
			t.Errorf("remove integration test cgroup: %v", err)
		}
	})

	tcpListener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tcpListener.Close() })
	listenerPort := uint16(tcpListener.Addr().(*net.TCPAddr).Port)
	udpListener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: int(listenerPort)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = udpListener.Close() })
	if err = ipv4.NewPacketConn(udpListener).SetControlMessage(ipv4.FlagDst, true); err != nil {
		t.Fatal(err)
	}

	redirectPrefix := netip.MustParsePrefix("127.128.0.0/9")
	backend, err := PrepareCgroup(CgroupConfig{
		Path:         cgroupPath,
		EnableTCP:    true,
		EnableUDP:    true,
		RedirectIPv4: redirectPrefix,
		MapCapacity:  DefaultCgroupMapCapacity(),
		UDPTimeout:   5 * time.Minute,
		Policy: CgroupPolicy{
			EnableBypassCIDR: true,
			HijackDNS:        true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err = backend.Close(); err != nil {
			t.Errorf("close eBPF backend: %v", err)
		}
	})
	if _, err = backend.UpdateBypassCIDR([]netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")}); err != nil {
		t.Fatal(err)
	}
	if err = backend.LoadPrograms(listenerPort); err != nil {
		t.Fatal(err)
	}
	if err = backend.Attach(); err != nil {
		t.Fatal(err)
	}
	protectedTCP := prepareProtectedIntegrationSocket(t, backend, "tcp4", unix.SOCK_STREAM, unix.IPPROTO_TCP)
	defer protectedTCP.Close()
	protectedUDP := prepareProtectedIntegrationSocket(t, backend, "udp4", unix.SOCK_DGRAM, unix.IPPROTO_UDP)
	defer protectedUDP.Close()

	readyReader, readyWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer readyWriter.Close()
	continueReader, continueWriter, err := os.Pipe()
	if err != nil {
		readyReader.Close()
		t.Fatal(err)
	}
	defer continueWriter.Close()
	var helperOutput bytes.Buffer
	helper := exec.Command(os.Args[0], "-test.run=^TestCgroupBackendTrafficHelper$")
	helper.Env = append(os.Environ(), integrationTrafficHelperEnv+"=1")
	helper.ExtraFiles = []*os.File{readyReader, protectedTCP, protectedUDP, continueReader}
	helper.Stdout = &helperOutput
	helper.Stderr = &helperOutput
	if err = helper.Start(); err != nil {
		readyReader.Close()
		continueReader.Close()
		t.Fatal(err)
	}
	readyReader.Close()
	continueReader.Close()
	protectedTCP.Close()
	protectedUDP.Close()
	helperWaited := false
	t.Cleanup(func() {
		if helperWaited {
			return
		}
		_ = helper.Process.Kill()
		_ = helper.Wait()
	})
	if err = os.WriteFile(
		filepath.Join(cgroupPath, "cgroup.procs"),
		[]byte(strconv.Itoa(helper.Process.Pid)),
		0,
	); err != nil {
		t.Fatal(err)
	}
	if _, err = readyWriter.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	if err = readyWriter.Close(); err != nil {
		t.Fatal(err)
	}

	if err = tcpListener.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	tcpConnection, err := tcpListener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	tcpPayload := make([]byte, 3)
	if _, err = io.ReadFull(tcpConnection, tcpPayload); err != nil {
		tcpConnection.Close()
		t.Fatal(err)
	}
	tcpRedirectDestination := tcpConnection.LocalAddr().(*net.TCPAddr).AddrPort()
	if err = tcpConnection.Close(); err != nil {
		t.Fatal(err)
	}
	if string(tcpPayload) != "tcp" {
		t.Fatalf("unexpected TCP payload: %q", tcpPayload)
	}
	if !redirectPrefix.Contains(tcpRedirectDestination.Addr()) {
		t.Fatalf("unexpected TCP redirect address: %v", tcpRedirectDestination)
	}
	tcpOriginal, err := backend.TakeOriginal(ProtocolTCP, tcpRedirectDestination)
	if err != nil {
		t.Fatal(err)
	}
	if expected := netip.MustParseAddrPort("198.51.100.10:443"); tcpOriginal.Destination != expected {
		t.Fatalf("unexpected TCP original destination: %v", tcpOriginal.Destination)
	}
	testLookupAndDeleteFallback(t, backend)

	if err = udpListener.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	udpPayload := make([]byte, 3)
	udpOOB := make([]byte, 128)
	n, oobN, _, _, err := udpListener.ReadMsgUDPAddrPort(udpPayload, udpOOB)
	if err != nil {
		t.Fatal(err)
	}
	if string(udpPayload[:n]) != "udp" {
		t.Fatalf("unexpected UDP payload: %q", udpPayload[:n])
	}
	var controlMessage ipv4.ControlMessage
	if err = controlMessage.Parse(udpOOB[:oobN]); err != nil {
		t.Fatal(err)
	}
	udpRedirectAddress, loaded := netip.AddrFromSlice(controlMessage.Dst)
	if !loaded {
		t.Fatalf("invalid UDP redirect address: %v", controlMessage.Dst)
	}
	udpRedirectAddress = udpRedirectAddress.Unmap()
	if !redirectPrefix.Contains(udpRedirectAddress) {
		t.Fatalf("unexpected UDP redirect address: %v", udpRedirectAddress)
	}
	flowCacheEnabled := backend.udpFlowMapFD >= 0
	if flowCacheEnabled {
		if _, err = backend.UpdateBypassCIDR([]netip.Prefix{
			netip.MustParsePrefix("192.168.0.0/16"),
			netip.MustParsePrefix("198.51.100.20/32"),
		}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = continueWriter.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	if err = continueWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err = udpListener.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	n, oobN, _, _, err = udpListener.ReadMsgUDPAddrPort(udpPayload, udpOOB)
	if err != nil {
		t.Fatal("cached UDP flow was not redirected after bypass policy update: ", err)
	}
	if string(udpPayload[:n]) != "two" {
		t.Fatalf("unexpected cached UDP payload: %q", udpPayload[:n])
	}
	if err = controlMessage.Parse(udpOOB[:oobN]); err != nil {
		t.Fatal(err)
	}
	secondRedirectAddress, loaded := netip.AddrFromSlice(controlMessage.Dst)
	if !loaded || secondRedirectAddress.Unmap() != udpRedirectAddress {
		t.Fatalf("UDP flow token changed: first=%v second=%v", udpRedirectAddress, secondRedirectAddress)
	}
	udpRedirectDestination := netip.AddrPortFrom(udpRedirectAddress, listenerPort)
	udpOriginal, err := backend.LookupOriginal(
		ProtocolUDP,
		udpRedirectDestination,
	)
	if err != nil {
		t.Fatal(err)
	}
	if expected := netip.MustParseAddrPort("198.51.100.20:5353"); udpOriginal.Destination != expected {
		t.Fatalf("unexpected UDP original destination: %v", udpOriginal.Destination)
	}
	redirectKey, err := makeListenerLookupKey(ProtocolUDP, udpRedirectDestination)
	if err != nil {
		t.Fatal(err)
	}
	var originalValue originalDestinationValue
	if err = lookupMap(backend.udpRedirectMapFD, unsafe.Pointer(&redirectKey), unsafe.Pointer(&originalValue)); err != nil {
		t.Fatal(err)
	}
	flowKey := makeUDPFlowKey(originalValue)
	var cachedFlow udpFlowValue
	if flowCacheEnabled {
		if err = lookupMap(backend.udpFlowMapFD, unsafe.Pointer(&flowKey), unsafe.Pointer(&cachedFlow)); err != nil {
			t.Fatal("lookup unconnected UDP flow cache: ", err)
		}
		if cachedFlow.Action != udpFlowActionProxy || cachedFlow.Listener != redirectKey {
			t.Fatalf("unexpected cached UDP flow: %+v", cachedFlow)
		}
	}
	if err = backend.DeleteRedirect(ProtocolUDP, udpRedirectDestination); err != nil {
		t.Fatal(err)
	}
	if flowCacheEnabled {
		if err = lookupMap(backend.udpFlowMapFD, unsafe.Pointer(&flowKey), unsafe.Pointer(&cachedFlow)); !errors.Is(err, unix.ENOENT) {
			t.Fatalf("UDP flow cache survived redirect cleanup: %v", err)
		}
	}

	if err = helper.Wait(); err != nil {
		helperWaited = true
		t.Fatalf("traffic helper: %v: %s", err, helperOutput.Bytes())
	}
	helperWaited = true

	if err = tcpListener.SetDeadline(time.Now().Add(250 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	unexpectedTCP, acceptErr := tcpListener.AcceptTCP()
	if acceptErr == nil {
		unexpectedTCP.Close()
		t.Fatal("protected TCP socket was redirected back into the eBPF listener")
	}
	if networkErr, loaded := acceptErr.(net.Error); !loaded || !networkErr.Timeout() {
		t.Fatalf("check protected TCP socket: %v", acceptErr)
	}
	if err = udpListener.SetReadDeadline(time.Now().Add(250 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, err = udpListener.ReadMsgUDPAddrPort(udpPayload, udpOOB); err == nil {
		t.Fatal("protected UDP socket was redirected back into the eBPF listener")
	} else if networkErr, loaded := err.(net.Error); !loaded || !networkErr.Timeout() {
		t.Fatalf("check protected UDP socket: %v", err)
	}
}

func testLookupAndDeleteFallback(t *testing.T, backend *CgroupBackend) {
	t.Helper()
	redirectDestination := netip.MustParseAddrPort("127.128.0.250:65530")
	originalDestination := netip.MustParseAddrPort("203.0.113.20:8443")
	key, err := makeListenerLookupKey(ProtocolTCP, redirectDestination)
	if err != nil {
		t.Fatal(err)
	}
	var value originalDestinationValue
	value.Protocol = ProtocolTCP
	value.Port = originalDestination.Port()
	if err = encodeAddress(&value.Family, &value.Addr, originalDestination.Addr()); err != nil {
		t.Fatal(err)
	}
	if err = updateMap(backend.tcpRedirectMapFD, unsafe.Pointer(&key), unsafe.Pointer(&value)); err != nil {
		t.Fatal(err)
	}
	backend.lookupAndDeleteMode.Store(mapLookupAndDeleteUnsupported)
	original, err := backend.TakeOriginal(ProtocolTCP, redirectDestination)
	if err != nil {
		t.Fatal(err)
	}
	if original.Destination != originalDestination {
		t.Fatalf("unexpected fallback original destination: %v", original.Destination)
	}
	if _, err = backend.LookupOriginal(ProtocolTCP, redirectDestination); !errors.Is(err, unix.ENOENT) {
		t.Fatalf("fallback did not consume redirect mapping: %v", err)
	}
}

func TestCgroupBackendTGIDSelfBypassIntegration(t *testing.T) {
	requireEBPFIntegration(t, "test TGID self bypass")
	cgroupMount, err := DetectCgroup2Mount()
	if err != nil {
		t.Fatal(err)
	}
	cgroupPath, err := os.MkdirTemp(cgroupMount, "sing-box-ebpf-tgid-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Remove(cgroupPath); err != nil {
			t.Errorf("remove TGID integration cgroup: %v", err)
		}
	})

	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	listenerPort := uint16(listener.Addr().(*net.TCPAddr).Port)
	backend, err := PrepareCgroup(CgroupConfig{
		Path:         cgroupPath,
		EnableTCP:    true,
		RedirectIPv4: netip.MustParsePrefix("127.128.0.0/9"),
		MapCapacity:  DefaultCgroupMapCapacity(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := backend.Close(); err != nil {
			t.Errorf("close TGID integration backend: %v", err)
		}
	})

	readyReader, readyWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer readyWriter.Close()
	var helperOutput bytes.Buffer
	helper := exec.Command(os.Args[0], "-test.run=^TestCgroupBackendTGIDSelfBypassHelper$")
	helper.Env = append(os.Environ(), integrationTGIDHelperEnv+"=1")
	helper.ExtraFiles = []*os.File{readyReader}
	helper.Stdout = &helperOutput
	helper.Stderr = &helperOutput
	if err = helper.Start(); err != nil {
		readyReader.Close()
		t.Fatal(err)
	}
	readyReader.Close()
	helperWaited := false
	t.Cleanup(func() {
		if helperWaited {
			return
		}
		_ = helper.Process.Kill()
		_ = helper.Wait()
	})
	if err = backend.loadPrograms(listenerPort, uint32(helper.Process.Pid)); err != nil {
		t.Fatal(err)
	}
	if backend.SelfBypassMode() != "tgid" {
		t.Skip("kernel rejected TGID self bypass and loaded the socket-cookie fallback")
	}
	if err = backend.Attach(); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(cgroupPath, "cgroup.procs"), []byte(strconv.Itoa(helper.Process.Pid)), 0); err != nil {
		t.Fatal(err)
	}
	if _, err = readyWriter.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	if err = readyWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err = listener.SetDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	connection, acceptErr := listener.AcceptTCP()
	if acceptErr == nil {
		connection.Close()
		t.Fatal("TGID self traffic was redirected into the eBPF listener")
	}
	if networkErr, loaded := acceptErr.(net.Error); !loaded || !networkErr.Timeout() {
		t.Fatalf("check TGID self bypass: %v", acceptErr)
	}
	if err = helper.Wait(); err != nil {
		helperWaited = true
		t.Fatalf("TGID traffic helper: %v: %s", err, helperOutput.Bytes())
	}
	helperWaited = true
}

func TestCgroupBackendTGIDSelfBypassHelper(t *testing.T) {
	if os.Getenv(integrationTGIDHelperEnv) != "1" {
		t.Skip("TGID self-bypass helper")
	}
	readyPipe := os.NewFile(3, "cgroup-ready")
	if readyPipe == nil {
		t.Fatal("missing cgroup ready pipe")
	}
	defer readyPipe.Close()
	if _, err := io.ReadFull(readyPipe, make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	fileDescriptor, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, unix.IPPROTO_TCP)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fileDescriptor)
	err = unix.Connect(fileDescriptor, &unix.SockaddrInet4{Port: 443, Addr: [4]byte{198, 51, 100, 30}})
	if err != nil && !errors.Is(err, unix.EINPROGRESS) && !errors.Is(err, unix.ENETUNREACH) {
		t.Fatal(err)
	}
}

func prepareProtectedIntegrationSocket(
	t *testing.T,
	backend *CgroupBackend,
	network string,
	socketType int,
	protocol int,
) *os.File {
	t.Helper()
	fileDescriptor, err := unix.Socket(unix.AF_INET, socketType|unix.SOCK_CLOEXEC, protocol)
	if err != nil {
		t.Fatal(err)
	}
	file := os.NewFile(uintptr(fileDescriptor), "protected-"+network)
	if file == nil {
		unix.Close(fileDescriptor)
		t.Fatal("create protected socket file")
	}
	rawConnection, err := file.SyscallConn()
	if err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err = backend.SocketProtectFunc()(network, "", rawConnection); err != nil {
		file.Close()
		t.Fatal(err)
	}
	return file
}

func TestCgroupBackendTrafficHelper(t *testing.T) {
	if os.Getenv(integrationTrafficHelperEnv) != "1" {
		t.Skip("integration traffic helper")
	}
	readyPipe := os.NewFile(3, "cgroup-ready")
	if readyPipe == nil {
		t.Fatal("missing cgroup ready pipe")
	}
	defer readyPipe.Close()
	ready := make([]byte, 1)
	if _, err := io.ReadFull(readyPipe, ready); err != nil {
		t.Fatal(err)
	}

	tcpConnection, err := net.DialTimeout("tcp4", "198.51.100.10:443", 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tcpConnection.Write([]byte("tcp")); err != nil {
		tcpConnection.Close()
		t.Fatal(err)
	}
	if err = tcpConnection.Close(); err != nil {
		t.Fatal(err)
	}

	udpConnection, err := net.ListenUDP("udp4", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer udpConnection.Close()
	if err = udpConnection.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	destination := &net.UDPAddr{IP: net.ParseIP("198.51.100.20"), Port: 5353}
	if _, err = udpConnection.WriteToUDP([]byte("udp"), destination); err != nil {
		t.Fatal(err)
	}
	continuePipe := os.NewFile(6, "continue-udp")
	if continuePipe == nil {
		t.Fatal("missing UDP continue pipe")
	}
	defer continuePipe.Close()
	if _, err = io.ReadFull(continuePipe, make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	if _, err = udpConnection.WriteToUDP([]byte("two"), destination); err != nil {
		t.Fatal(err)
	}

	protectedTCP := os.NewFile(4, "protected-tcp")
	if protectedTCP == nil {
		t.Fatal("missing protected TCP socket")
	}
	defer protectedTCP.Close()
	protectedTCPDescriptor := int(protectedTCP.Fd())
	if err = unix.SetNonblock(protectedTCPDescriptor, true); err != nil {
		t.Fatal(err)
	}
	if err = unix.Connect(protectedTCPDescriptor, &unix.SockaddrInet4{
		Port: 443,
		Addr: [4]byte{203, 0, 113, 10},
	}); err != nil && !errors.Is(err, unix.EINPROGRESS) && !errors.Is(err, unix.ENETUNREACH) {
		t.Fatal(err)
	}

	protectedUDP := os.NewFile(5, "protected-udp")
	if protectedUDP == nil {
		t.Fatal("missing protected UDP socket")
	}
	defer protectedUDP.Close()
	if err = unix.Sendto(int(protectedUDP.Fd()), []byte("protected"), 0, &unix.SockaddrInet4{
		Port: 5353,
		Addr: [4]byte{203, 0, 113, 11},
	}); err != nil && !errors.Is(err, unix.ENETUNREACH) {
		t.Fatal(err)
	}
}

func TestSharedNetworkStandaloneProgramLoadIntegration(t *testing.T) {
	requireEBPFIntegration(t, "load standalone shared-network programs")
	backend := prepareSharedNetworkProgramLoad(t, nil, true)
	updated, err := backend.UpdateBypassCIDR([]netip.Prefix{
		netip.MustParsePrefix("198.51.100.0/24"),
		netip.MustParsePrefix("2001:db8::/32"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !updated {
		t.Fatal("standalone shared-network bypass policy was not updated")
	}
	if ipv4Count, ipv6Count := backend.BypassCIDRCount(); ipv4Count != 1 || ipv6Count != 1 {
		t.Fatalf("unexpected standalone bypass CIDR count: ipv4=%d ipv6=%d", ipv4Count, ipv6Count)
	}
}

func requireEBPFIntegration(t *testing.T, action string) {
	t.Helper()
	if os.Getenv(integrationTestEnv) != "1" {
		t.Skip("set " + integrationTestEnv + "=1 to " + action)
	}
	if os.Geteuid() != 0 {
		t.Fatal("eBPF integration test requires root")
	}
}

func containsProgram(programs []string, expected string) bool {
	for _, program := range programs {
		if program == expected {
			return true
		}
	}
	return false
}
