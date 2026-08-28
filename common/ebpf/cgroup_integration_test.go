//go:build with_ebpf && (linux || android) && ebpf_integration

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
	integrationCookieHelperEnv  = "SING_BOX_EBPF_COOKIE_HELPER"
)

func TestCgroupBackendProgramLoadIntegration(t *testing.T) {
	requireEBPFIntegration(t, "load eBPF programs")
	addressFamilies := []struct {
		name       string
		enableIPv6 bool
	}{
		{name: "ipv4"},
		{name: "dual_stack", enableIPv6: true},
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
				name := addressFamily.name + "/" + protocol.name + "/" + dnsMode
				t.Run(name, func(t *testing.T) {
					testCgroupBackendProgramLoad(t, cgroupProgramLoadOptions{
						enableTCP:  protocol.enableTCP,
						enableUDP:  protocol.enableUDP,
						enableIPv6: addressFamily.enableIPv6,
						hijackDNS:  hijackDNS,
					})
				})
			}
		}
	}
	t.Run("bypass_private_address", func(t *testing.T) {
		testCgroupBackendProgramLoad(t, cgroupProgramLoadOptions{
			enableTCP:            true,
			enableUDP:            true,
			enableIPv6:           true,
			bypassPrivateAddress: true,
		})
	})
	t.Run("dns_respect_policy", func(t *testing.T) {
		testCgroupBackendProgramLoad(t, cgroupProgramLoadOptions{
			enableTCP:        true,
			enableUDP:        true,
			enableIPv6:       true,
			hijackDNS:        true,
			dnsRespectBypass: true,
		})
	})
}

func TestCgroupConnectedUDPRecoveryIntegration(t *testing.T) {
	requireEBPFIntegration(t, "recover connected UDP redirect state")
	backend, err := PrepareCgroup(CgroupConfig{
		Path:         os.Getenv("SING_BOX_EBPF_INTEGRATION_CGROUP"),
		EnableUDP:    true,
		RedirectIPv4: netip.MustParsePrefix("127.128.0.0/9"),
		MapCapacity:  DefaultCgroupMapCapacity(),
		UDPTimeout:   5 * time.Minute,
		Policy:       CgroupPolicy{DNSMode: DNSModeHijack},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := backend.Close(); err != nil {
			t.Errorf("close eBPF backend: %v", err)
		}
	})

	// Exercise the fallback recovery independently of host sock-release support.
	backend.access.Lock()
	backend.runtime.socket_release_supported = false
	backend.access.Unlock()
	installState := func(listenerDestination netip.AddrPort, cookie uint64, peerAddress netip.Addr) listenerLookupKey {
		t.Helper()
		listener, installErr := makeListenerLookupKey(ProtocolUDP, listenerDestination)
		if installErr != nil {
			t.Fatal(installErr)
		}
		peer := udpPeerValue{Family: addressFamilyIPv4, Protocol: ProtocolUDP, Port: 53}
		copy(peer.Addr[:4], peerAddress.AsSlice())
		peerKey := udpPeerKey{SocketCookie: cookie}
		if installErr = updateMap(
			backend.runtime.udp_token_map_fd,
			unsafe.Pointer(&cookie),
			unsafe.Pointer(&listener),
		); installErr != nil {
			t.Fatal(installErr)
		}
		if installErr = updateMap(
			backend.runtime.udp_peer_map_fd,
			unsafe.Pointer(&peerKey),
			unsafe.Pointer(&peer),
		); installErr != nil {
			t.Fatal(installErr)
		}
		return listener
	}
	recoverState := func(listenerDestination netip.AddrPort, expected netip.AddrPort) {
		t.Helper()
		if _, recoverErr := backend.LookupOriginal(ProtocolUDP, listenerDestination); !errors.Is(recoverErr, unix.ENOENT) {
			t.Fatalf("unexpected redirect before recovery: %v", recoverErr)
		}
		recovered, recoverErr := backend.RecoverConnectedUDPOriginal(listenerDestination)
		if recoverErr != nil {
			t.Fatal(recoverErr)
		}
		if recovered.Destination != expected || !recovered.ConnectedUDP {
			t.Fatalf("unexpected recovered destination: %+v", recovered)
		}
		loaded, recoverErr := backend.LookupOriginal(ProtocolUDP, listenerDestination)
		if recoverErr != nil {
			t.Fatal(recoverErr)
		}
		if loaded.Destination != recovered.Destination ||
			loaded.ConnectedUDP != recovered.ConnectedUDP ||
			!bytes.Equal(loaded.SourceMAC, recovered.SourceMAC) {
			t.Fatalf("restored redirect mismatch: loaded=%+v recovered=%+v", loaded, recovered)
		}
	}
	listenerDestination := netip.MustParseAddrPort("127.128.10.20:5300")
	installState(listenerDestination, 0x1020304050607080, netip.MustParseAddr("192.0.2.53"))
	recoverState(listenerDestination, netip.MustParseAddrPort("192.0.2.53:53"))

	// Force the legacy iterator after the automatic probe so both paths stay
	// covered on kernels that implement BPF_MAP_LOOKUP_BATCH.
	backend.access.Lock()
	backend.connectedUDPTokenLookupSupport.mode.Store(mapBatchUnsupported)
	backend.access.Unlock()
	legacyListenerDestination := netip.MustParseAddrPort("127.128.10.21:5301")
	installState(legacyListenerDestination, 0x1020304050607081, netip.MustParseAddr("192.0.2.54"))
	recoverState(legacyListenerDestination, netip.MustParseAddrPort("192.0.2.54:53"))
}

func TestCgroupUDPRecoveryConsumptionIntegration(t *testing.T) {
	requireEBPFIntegration(t, "consume recovered UDP redirect state")
	backend, err := PrepareCgroup(CgroupConfig{
		Path:         os.Getenv("SING_BOX_EBPF_INTEGRATION_CGROUP"),
		EnableUDP:    true,
		RedirectIPv4: netip.MustParsePrefix("127.128.0.0/9"),
		MapCapacity:  DefaultCgroupMapCapacity(),
		UDPTimeout:   5 * time.Minute,
		Policy:       CgroupPolicy{DNSMode: DNSModeHijack},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := backend.Close(); err != nil {
			t.Errorf("close eBPF backend: %v", err)
		}
	})
	original := originalDestinationValue{
		Family:   addressFamilyIPv4,
		Protocol: ProtocolUDP,
		Port:     5353,
	}
	copy(original.Addr[:4], netip.MustParseAddr("192.0.2.53").AsSlice())
	installRecovery := func(destination netip.AddrPort) listenerLookupKey {
		t.Helper()
		key, keyErr := makeListenerLookupKey(ProtocolUDP, destination)
		if keyErr != nil {
			t.Fatal(keyErr)
		}
		if keyErr = updateMap(
			backend.udpRecoveryMapFD,
			unsafe.Pointer(&key),
			unsafe.Pointer(&original),
		); keyErr != nil {
			t.Fatal(keyErr)
		}
		return key
	}
	assertRecovery := func(key listenerLookupKey, expected bool) {
		t.Helper()
		var loaded originalDestinationValue
		lookupErr := lookupMap(
			backend.udpRecoveryMapFD,
			unsafe.Pointer(&key),
			unsafe.Pointer(&loaded),
		)
		if expected {
			if lookupErr != nil || loaded != original {
				t.Fatalf("UDP recovery state was not preserved: value=%+v err=%v", loaded, lookupErr)
			}
		} else if !errors.Is(lookupErr, unix.ENOENT) {
			t.Fatalf("consumed UDP recovery state remains: %v", lookupErr)
		}
	}

	destination := netip.MustParseAddrPort("127.128.10.30:5300")
	key := installRecovery(destination)
	redirectMapFD := backend.udpRedirectMapFD
	backend.udpRedirectMapFD = -1
	_, recoverErr := backend.RecoverUDPOriginal(destination)
	backend.udpRedirectMapFD = redirectMapFD
	if recoverErr == nil {
		t.Fatal("UDP recovery unexpectedly succeeded with unavailable redirect map")
	}
	assertRecovery(key, true)

	recovered, err := backend.RecoverUDPOriginal(destination)
	if err != nil {
		t.Fatal(err)
	}
	if recovered.Destination != netip.MustParseAddrPort("192.0.2.53:5353") {
		t.Fatalf("unexpected recovered destination: %+v", recovered)
	}
	assertRecovery(key, backend.udpRecoveryConsumeMode.Load() == mapLookupAndDeleteUnsupported)

	legacyDestination := netip.MustParseAddrPort("127.128.10.31:5301")
	legacyKey := installRecovery(legacyDestination)
	backend.udpRecoveryConsumeMode.Store(mapLookupAndDeleteUnsupported)
	if _, err = backend.RecoverUDPOriginal(legacyDestination); err != nil {
		t.Fatal(err)
	}
	assertRecovery(legacyKey, true)
}

func TestCgroupUDPReplyRedirectIntegration(t *testing.T) {
	requireEBPFIntegration(t, "reserve userspace UDP reply redirects")
	backend, err := PrepareCgroup(CgroupConfig{
		Path:         os.Getenv("SING_BOX_EBPF_INTEGRATION_CGROUP"),
		EnableUDP:    true,
		EnableIPv6:   true,
		RedirectIPv4: netip.MustParsePrefix("127.128.0.0/9"),
		RedirectIPv6: netip.MustParsePrefix("fd53:696e:672d:626f::/64"),
		MapCapacity:  DefaultCgroupMapCapacity(),
		UDPTimeout:   5 * time.Minute,
		Policy:       CgroupPolicy{DNSMode: DNSModeHijack},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := backend.Close(); err != nil {
			t.Errorf("close eBPF backend: %v", err)
		}
	})
	for _, destination := range []netip.AddrPort{
		netip.MustParseAddrPort("192.0.2.53:5000"),
		netip.MustParseAddrPort("[2001:db8::53]:5000"),
	} {
		t.Run(destination.String(), func(t *testing.T) {
			token, reserveErr := backend.ReserveUDPReplyRedirect(destination, 5300)
			if reserveErr != nil {
				t.Fatal(reserveErr)
			}
			listener := netip.AddrPortFrom(token, 5300)
			original, lookupErr := backend.LookupOriginal(ProtocolUDP, listener)
			if lookupErr != nil {
				t.Fatal(lookupErr)
			}
			if original.Destination != destination || original.ConnectedUDP {
				t.Fatalf("unexpected UDP reply redirect: %+v", original)
			}
			if deleteErr := backend.DeleteRedirect(ProtocolUDP, listener); deleteErr != nil {
				t.Fatal(deleteErr)
			}
			if _, lookupErr = backend.LookupOriginal(ProtocolUDP, listener); !errors.Is(lookupErr, unix.ENOENT) {
				t.Fatalf("UDP reply redirect survived deletion: %v", lookupErr)
			}
		})
	}
}

func integrationDNSMode(hijackDNS bool, dnsRespectBypass bool) DNSMode {
	if !hijackDNS {
		return DNSModeOff
	}
	if dnsRespectBypass {
		return DNSModeRespectPolicy
	}
	return DNSModeHijack
}

type cgroupProgramLoadOptions struct {
	enableTCP            bool
	enableUDP            bool
	enableIPv6           bool
	hijackDNS            bool
	bypassPrivateAddress bool
	dnsRespectBypass     bool
}

func testCgroupBackendProgramLoad(t *testing.T, options cgroupProgramLoadOptions) {
	backend, err := PrepareCgroup(CgroupConfig{
		Path:         os.Getenv("SING_BOX_EBPF_INTEGRATION_CGROUP"),
		EnableTCP:    options.enableTCP,
		EnableUDP:    options.enableUDP,
		EnableIPv6:   options.enableIPv6,
		RedirectIPv4: netip.MustParsePrefix("127.128.0.0/9"),
		RedirectIPv6: netip.MustParsePrefix("fd53:696e:672d:626f::/64"),
		MapCapacity:  DefaultCgroupMapCapacity(),
		UDPTimeout:   5 * time.Minute,
		Policy: CgroupPolicy{
			DNSMode:              integrationDNSMode(options.hijackDNS, options.dnsRespectBypass),
			BypassPrivateAddress: options.bypassPrivateAddress,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := backend.Close(); err != nil {
			t.Errorf("close eBPF backend: %v", err)
		}
	})
	if options.enableTCP {
		sweep, sweepErr := backend.SweepStaleTCPRedirects(time.Nanosecond, mapBatchMaxEntries)
		if sweepErr != nil {
			t.Fatal(sweepErr)
		}
		if sweep.Scanned != 0 || sweep.Removed != 0 || !sweep.Complete {
			t.Fatalf("unexpected empty TCP sweep result: %+v", sweep)
		}
		failures, failureErr := backend.TCPRedirectReservationFailures()
		if failureErr != nil || failures != 0 {
			t.Fatalf("unexpected TCP redirect reservation failures: count=%d err=%v", failures, failureErr)
		}
	}
	pendingSocket := prepareProtectedIntegrationSocket(t, backend, "udp4", unix.SOCK_DGRAM, unix.IPPROTO_UDP)
	defer pendingSocket.Close()
	pendingCookie, err := readSocketCookie(pendingSocket.Fd())
	if err != nil {
		t.Fatal(err)
	}
	var protectedValue uint8
	if err = lookupMap(backend.socketBypassMapFD, unsafe.Pointer(&pendingCookie), unsafe.Pointer(&protectedValue)); err != nil {
		t.Fatalf("socket protected before program load was not registered: %v", err)
	}
	if err = backend.loadPrograms(65532); err != nil {
		t.Fatal(err)
	}
	if protectedValue != 1 {
		t.Fatalf("unexpected protected socket value: %d", protectedValue)
	}

	programs := backend.AttachedPrograms()
	if len(programs) == 0 {
		t.Fatal("no cgroup program was built")
	}
	if options.enableUDP && usesSocketReleaseForTest(backend) && !containsProgram(programs, "sb_ebpf_rel (cgroup/sock_release)") {
		t.Fatalf("socket-release program was not reported: %v", programs)
	}
	if options.enableUDP && !usesSocketReleaseForTest(backend) {
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
			prepareSharedNetworkProgramLoad(t, backend, hijackDNS, false, true)
		})
	}
	t.Run("respect_policy", func(t *testing.T) {
		prepareSharedNetworkProgramLoad(t, backend, true, true, true)
	})
	t.Run("proxy_private", func(t *testing.T) {
		prepareSharedNetworkProgramLoad(t, backend, true, false, false)
	})
}

func TestSharedNetworkGenerationCleanupIntegration(t *testing.T) {
	requireEBPFIntegration(t, "validate shared-network generation-aware cleanup")
	backend, err := PrepareSharedNetwork(nil, SharedNetworkConfig{
		ListenerPort: 65531,
		EnableTCP:    true,
		RedirectIPv4: netip.MustParsePrefix("127.128.0.0/9"),
		MapCapacity: SharedNetworkMapCapacities{
			Proxy:  16,
			Bypass: 1,
		},
		UDPTimeout: 5 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })

	originalKey := sharedNetworkOriginalKey{
		InterfaceIndex: 7,
		Family:         addressFamilyIPv4,
		Protocol:       ProtocolTCP,
		ClientPort:     53000,
		OriginalPort:   443,
	}
	copy(originalKey.ClientAddr[:], netip.MustParseAddr("192.0.2.2").AsSlice())
	copy(originalKey.OriginalAddr[:], netip.MustParseAddr("198.51.100.10").AsSlice())
	token := netip.MustParseAddr("127.200.1.2").As4()
	var tokenAddress [16]byte
	copy(tokenAddress[:], token[:])
	oldFlow := makeSharedNetworkFlowHandleFromOriginal(originalKey, tokenAddress, 65531, 10)
	newFlow := makeSharedNetworkFlowHandleFromOriginal(originalKey, tokenAddress, 65531, 11)
	newTokenValue := sharedNetworkTokenValue{
		TokenAddr:  tokenAddress,
		Generation: newFlow.generation,
		LastSeenNS: 1,
	}
	newOriginalValue := sharedNetworkOriginalValue{
		Family:         addressFamilyIPv4,
		Protocol:       ProtocolTCP,
		Port:           originalKey.OriginalPort,
		Addr:           originalKey.OriginalAddr,
		InterfaceIndex: originalKey.InterfaceIndex,
		Generation:     newFlow.generation,
	}
	if err = updateMap(
		backend.runtime.flow_by_original_map_fd,
		unsafe.Pointer(&originalKey),
		unsafe.Pointer(&newTokenValue),
	); err != nil {
		t.Fatal(err)
	}
	if err = updateMap(
		backend.runtime.flow_by_token_map_fd,
		unsafe.Pointer(&newFlow.listenerKey),
		unsafe.Pointer(&newOriginalValue),
	); err != nil {
		t.Fatal(err)
	}
	if removed, cleanupErr := backend.deleteFlowGenerationLocked(oldFlow); cleanupErr != nil || removed {
		t.Fatalf("old generation removed current state: removed=%t err=%v", removed, cleanupErr)
	}
	if err = backend.validateFlowGenerationLocked(newFlow); err != nil {
		t.Fatal("current generation did not survive old cleanup: ", err)
	}
	if removed, cleanupErr := backend.deleteFlowGenerationLocked(newFlow); cleanupErr != nil || !removed {
		t.Fatalf("current generation was not removed: removed=%t err=%v", removed, cleanupErr)
	}
	var tokenValue sharedNetworkTokenValue
	if err = lookupMap(
		backend.runtime.flow_by_original_map_fd,
		unsafe.Pointer(&originalKey),
		unsafe.Pointer(&tokenValue),
	); !errors.Is(err, unix.ENOENT) {
		t.Fatalf("original state survived matching cleanup: %v", err)
	}
	var originalValue sharedNetworkOriginalValue
	if err = lookupMap(
		backend.runtime.flow_by_token_map_fd,
		unsafe.Pointer(&newFlow.listenerKey),
		unsafe.Pointer(&originalValue),
	); !errors.Is(err, unix.ENOENT) {
		t.Fatalf("token state survived matching cleanup: %v", err)
	}
}

func prepareSharedNetworkProgramLoad(t *testing.T, cgroupBackend *CgroupBackend, hijackDNS bool, dnsRespectBypass bool, bypassPrivateAddress bool) *SharedNetworkBackend {
	t.Helper()
	sharedBackend, err := PrepareSharedNetwork(cgroupBackend, SharedNetworkConfig{
		ListenerPort:         65531,
		EnableTCP:            true,
		EnableUDP:            true,
		DNSMode:              integrationDNSMode(hijackDNS, dnsRespectBypass),
		BypassPrivateAddress: bypassPrivateAddress,
		RedirectIPv4:         netip.MustParsePrefix("127.128.0.0/9"),
		RedirectIPv6:         netip.MustParsePrefix("fd53:696e:672d:626f::/64"),
		IncludeSourceMAC:     []MACAddress{{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}},
		ExcludeSourceMAC:     []MACAddress{{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}},
		MapCapacity:          DefaultSharedNetworkMapCapacities(),
		UDPTimeout:           5 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := sharedBackend.Close(); err != nil {
			t.Errorf("close shared-network token backend: %v", err)
		}
	})
	failures, failureErr := sharedBackend.TokenReservationFailures()
	if failureErr != nil || failures != 0 {
		t.Fatalf("unexpected token reservation failures: count=%d err=%v", failures, failureErr)
	}
	sweep, sweepErr := sharedBackend.SweepOrphanedFlows(time.Nanosecond, mapBatchMaxEntries)
	if sweepErr != nil {
		t.Fatal(sweepErr)
	}
	if sweep.Scanned != 0 || sweep.Removed != 0 || sweep.Retained != 0 ||
		sweep.Usage != (MapUsage{Capacity: sharedBackend.mapCapacity.Proxy}) {
		t.Fatalf("unexpected empty shared-network sweep result: %+v", sweep)
	}
	if sharedBackend.IngressProgramFD() < 0 || sharedBackend.EgressProgramFD() < 0 {
		t.Fatal("shared-network token programs were not loaded")
	}
	if dnsMode := integrationDNSMode(hijackDNS, dnsRespectBypass); sharedBackend.control.DNSMode != dnsMode {
		t.Fatalf("unexpected shared-network DNS mode: %d", sharedBackend.control.DNSMode)
	}
	if hasBypassPrivateAddress := sharedBackend.control.Flags&sharedNetworkFlagBypassPrivateAddress != 0; hasBypassPrivateAddress != bypassPrivateAddress {
		t.Fatalf("unexpected shared-network private-address bypass flag: %t", hasBypassPrivateAddress)
	}
	if sharedBackend.control.Flags&sharedNetworkFlagIncludeSourceMAC == 0 ||
		sharedBackend.control.Flags&sharedNetworkFlagExcludeSourceMAC == 0 {
		t.Fatal("shared-network source MAC policy is disabled")
	}
	if sharedBackend.control.Flags&sharedNetworkFlagBypassFlowCache == 0 {
		t.Fatal("shared-network bypass-flow cache lookup is disabled with source policy")
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
		if _, err = updateSharedBypassCIDRForTest(sharedBackend, []netip.Prefix{
			netip.MustParsePrefix("198.51.100.0/24"),
		}); err != nil {
			t.Fatal(err)
		}
	} else if err = sharedBackend.SetBypassCIDRState(1, 0); err != nil {
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
			DNSMode:          DNSModeHijack,
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
	if _, err = updateCgroupBypassCIDRForTest(backend, []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")}); err != nil {
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
		if _, err = updateCgroupBypassCIDRForTest(backend, []netip.Prefix{
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
	if _, err = backend.LookupOriginal(ProtocolUDP, udpRedirectDestination); !errors.Is(err, unix.ENOENT) {
		t.Fatalf("UDP redirect survived cleanup: %v", err)
	}
	recoveredOriginal, err := backend.RecoverUDPOriginal(udpRedirectDestination)
	if err != nil {
		t.Fatal("recover cleaned UDP redirect: ", err)
	}
	if recoveredOriginal.Destination != udpOriginal.Destination ||
		recoveredOriginal.ConnectedUDP != udpOriginal.ConnectedUDP ||
		!bytes.Equal(recoveredOriginal.SourceMAC, udpOriginal.SourceMAC) {
		t.Fatalf("unexpected recovered UDP original: %+v", recoveredOriginal)
	}
	if _, err = backend.LookupOriginal(ProtocolUDP, udpRedirectDestination); err != nil {
		t.Fatal("recovered UDP redirect was not restored: ", err)
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

func TestCgroupBackendSocketCookieSelfBypassIntegration(t *testing.T) {
	requireEBPFIntegration(t, "test socket-cookie self-bypass")
	cgroupMount, err := DetectCgroup2Mount()
	if err != nil {
		t.Fatal(err)
	}
	cgroupPath, err := os.MkdirTemp(cgroupMount, "sing-box-ebpf-cookie-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Remove(cgroupPath); err != nil {
			t.Errorf("remove cookie integration cgroup: %v", err)
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
			t.Errorf("close cookie integration backend: %v", err)
		}
	})

	protectedSocket := prepareProtectedIntegrationSocket(
		t,
		backend,
		"tcp4",
		unix.SOCK_STREAM|unix.SOCK_NONBLOCK,
		unix.IPPROTO_TCP,
	)
	defer protectedSocket.Close()
	readyReader, readyWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer readyWriter.Close()
	var helperOutput bytes.Buffer
	helper := exec.Command(os.Args[0], "-test.run=^TestCgroupBackendSocketCookieSelfBypassHelper$")
	helper.Env = append(os.Environ(), integrationCookieHelperEnv+"=1")
	helper.ExtraFiles = []*os.File{readyReader, protectedSocket}
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
	if err = backend.LoadPrograms(listenerPort); err != nil {
		t.Fatal(err)
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
		t.Fatal("protected traffic was redirected into the eBPF listener")
	}
	if networkErr, loaded := acceptErr.(net.Error); !loaded || !networkErr.Timeout() {
		t.Fatalf("check socket-cookie self bypass: %v", acceptErr)
	}
	if err = helper.Wait(); err != nil {
		helperWaited = true
		t.Fatalf("socket-cookie traffic helper: %v: %s", err, helperOutput.Bytes())
	}
	helperWaited = true
}

func TestCgroupBackendSocketCookieSelfBypassHelper(t *testing.T) {
	if os.Getenv(integrationCookieHelperEnv) != "1" {
		t.Skip("socket-cookie self-bypass helper")
	}
	readyPipe := os.NewFile(3, "cgroup-ready")
	if readyPipe == nil {
		t.Fatal("missing cgroup ready pipe")
	}
	defer readyPipe.Close()
	if _, err := io.ReadFull(readyPipe, make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	protectedSocket := os.NewFile(4, "protected-socket")
	if protectedSocket == nil {
		t.Fatal("missing protected socket")
	}
	defer protectedSocket.Close()
	err := unix.Connect(int(protectedSocket.Fd()), &unix.SockaddrInet4{Port: 443, Addr: [4]byte{198, 51, 100, 30}})
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
	cookie, err := readSocketCookie(file.Fd())
	if err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err = backend.RegisterProtectedSocket(cookie); err != nil {
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
	backend := prepareSharedNetworkProgramLoad(t, nil, true, false, true)
	updated, err := updateSharedBypassCIDRForTest(backend, []netip.Prefix{
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

func requireEBPFIntegration(t testing.TB, action string) {
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
