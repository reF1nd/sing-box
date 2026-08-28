//go:build with_ebpf && linux && ebpf_integration

package ebpf

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/netlink"
	ECommon "github.com/sagernet/sing-box/common/ebpf"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

const (
	sharedNetworkUDPClientHelperEnv  = "SING_BOX_EBPF_SHARED_UDP_CLIENT_HELPER"
	sharedNetworkTCPStressHelperEnv  = "SING_BOX_EBPF_SHARED_TCP_STRESS_HELPER"
	sharedNetworkTCPStressCountEnv   = "SING_BOX_EBPF_SHARED_TCP_STRESS_COUNT"
	sharedNetworkTCPStressWorkersEnv = "SING_BOX_EBPF_SHARED_TCP_STRESS_WORKERS"
)

func TestSharedNetworkTCPStressClientHelper(t *testing.T) {
	destination := os.Getenv(sharedNetworkTCPStressHelperEnv)
	if destination == "" {
		t.Skip("shared-network TCP stress helper")
	}
	count, err := strconv.Atoi(os.Getenv(sharedNetworkTCPStressCountEnv))
	if err != nil || count <= 0 {
		t.Fatal("invalid shared-network TCP stress count")
	}
	workers, err := strconv.Atoi(os.Getenv(sharedNetworkTCPStressWorkersEnv))
	if err != nil || workers <= 0 {
		t.Fatal("invalid shared-network TCP stress workers")
	}
	jobs := make(chan int)
	errors := make(chan error, count)
	var waitGroup sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			for range jobs {
				conn, dialErr := net.DialTimeout("tcp4", destination, 3*time.Second)
				if dialErr != nil {
					errors <- dialErr
					continue
				}
				_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
				if _, dialErr = conn.Write([]byte{1}); dialErr == nil {
					var response [1]byte
					_, dialErr = io.ReadFull(conn, response[:])
				}
				_ = conn.Close()
				if dialErr != nil {
					errors <- dialErr
				}
			}
		}()
	}
	for index := 0; index < count; index++ {
		jobs <- index
	}
	close(jobs)
	waitGroup.Wait()
	close(errors)
	for stressErr := range errors {
		t.Error(stressErr)
	}
}

func TestSharedNetworkTCPChurnIntegration(t *testing.T) {
	if os.Getenv("SING_BOX_EBPF_SHARED_INTEGRATION") != "1" {
		t.Skip("set SING_BOX_EBPF_SHARED_INTEGRATION=1 to run the root TC integration test")
	}
	if os.Geteuid() != 0 {
		t.Fatal("shared-network integration test requires root")
	}
	const (
		namespace         = "sb-ebpf-churn"
		hostLink          = "sbe-churn-h"
		peerLink          = "sbe-churn-p"
		stressConnections = 5000
		stressWorkers     = 128
	)
	runIP := func(arguments ...string) {
		t.Helper()
		command := exec.Command("ip", arguments...)
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("ip %s: %v: %s", strings.Join(arguments, " "), err, output)
		}
	}
	_ = exec.Command("ip", "netns", "del", namespace).Run()
	_ = exec.Command("ip", "link", "del", hostLink).Run()
	t.Cleanup(func() {
		_ = exec.Command("ip", "netns", "del", namespace).Run()
		_ = exec.Command("ip", "link", "del", hostLink).Run()
	})
	runIP("netns", "add", namespace)
	runIP("link", "add", hostLink, "type", "veth", "peer", "name", peerLink)
	runIP("link", "set", peerLink, "netns", namespace)
	runIP("address", "add", "192.0.2.1/24", "dev", hostLink)
	runIP("link", "set", hostLink, "up")
	runIP("netns", "exec", namespace, "ip", "link", "set", "lo", "up")
	runIP("netns", "exec", namespace, "ip", "address", "add", "192.0.2.2/24", "dev", peerLink)
	runIP("netns", "exec", namespace, "ip", "link", "set", peerLink, "up")
	runIP("netns", "exec", namespace, "ip", "route", "add", "default", "via", "192.0.2.1")

	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	listenerPort := uint16(listener.Addr().(*net.TCPAddr).Port)
	redirectPrefix := netip.MustParsePrefix("127.128.0.0/9")
	routeOwner := &Inbound{}
	routeOwner.localRoutes, err = addLocalRoutes([]netip.Prefix{redirectPrefix})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = routeOwner.removeLocalRoutes() })
	backend, err := ECommon.PrepareSharedNetwork(nil, ECommon.SharedNetworkConfig{
		ListenerPort: listenerPort,
		EnableTCP:    true,
		RedirectIPv4: redirectPrefix,
		MapCapacity: ECommon.SharedNetworkMapCapacities{
			Proxy:  8192,
			Bypass: 1,
		},
		UDPTimeout: 5 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	if err = backend.UpdateHostAddresses([]netip.Addr{netip.MustParseAddr("192.0.2.1")}); err != nil {
		t.Fatal(err)
	}
	manager := &sharedTCManager{
		backend:     backend,
		logger:      discardInterfaceLogger{},
		interfaces:  []string{hostLink},
		enableIPv4:  true,
		priority:    defaultSharedNetworkTCPriority,
		attachments: make(map[string]*sharedTCAttachment),
	}
	if err = manager.reconcile(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.closeAttachments() })

	serverErrors := make(chan error, stressConnections)
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		_ = listener.SetDeadline(time.Now().Add(45 * time.Second))
		var waitGroup sync.WaitGroup
		for index := 0; index < stressConnections; index++ {
			conn, acceptErr := listener.AcceptTCP()
			if acceptErr != nil {
				serverErrors <- acceptErr
				break
			}
			waitGroup.Add(1)
			go func() {
				defer waitGroup.Done()
				defer conn.Close()
				client := conn.RemoteAddr().(*net.TCPAddr).AddrPort()
				tokenDestination := conn.LocalAddr().(*net.TCPAddr).AddrPort()
				original, flow, lookupErr := backend.LookupFlow(ECommon.ProtocolTCP, client, tokenDestination)
				if lookupErr != nil {
					serverErrors <- lookupErr
					return
				}
				defer func() {
					if releaseErr := backend.ReleaseFlow(flow); releaseErr != nil {
						serverErrors <- releaseErr
					}
				}()
				if original.Destination != netip.MustParseAddrPort("10.0.0.1:18082") {
					serverErrors <- &unexpectedDestinationError{original.Destination}
					return
				}
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				var payload [1]byte
				if _, readErr := io.ReadFull(conn, payload[:]); readErr != nil {
					serverErrors <- readErr
					return
				}
				if _, writeErr := conn.Write(payload[:]); writeErr != nil {
					serverErrors <- writeErr
				}
			}()
		}
		waitGroup.Wait()
	}()

	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	stressContext, stressCancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer stressCancel()
	command := exec.CommandContext(
		stressContext,
		"ip", "netns", "exec", namespace,
		executable, "-test.run", "^TestSharedNetworkTCPStressClientHelper$",
	)
	command.Env = append(os.Environ(),
		sharedNetworkTCPStressHelperEnv+"=10.0.0.1:18082",
		fmt.Sprintf("%s=%d", sharedNetworkTCPStressCountEnv, stressConnections),
		fmt.Sprintf("%s=%d", sharedNetworkTCPStressWorkersEnv, stressWorkers),
	)
	if output, commandErr := command.CombinedOutput(); commandErr != nil {
		t.Fatalf("shared-network TCP stress client: %v: %s", commandErr, output)
	}
	<-serverDone
	close(serverErrors)
	for serverErr := range serverErrors {
		t.Error(serverErr)
	}
}

func TestSharedNetworkUDPClientHelper(t *testing.T) {
	helperMode := os.Getenv(sharedNetworkUDPClientHelperEnv)
	if helperMode == "" {
		t.Skip("shared-network integration test helper")
	}
	if helperMode != "1" {
		t.Fatalf("unknown shared-network UDP helper mode: %s", helperMode)
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	pinCurrentThread(t)
	conn, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6unspecified})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	destinations := []netip.AddrPort{
		netip.MustParseAddrPort("[2001:db8:1::1]:53"),
		netip.MustParseAddrPort("[2001:4860:4860::8888]:5353"),
		netip.MustParseAddrPort("[2001:db8:1::1]:53"),
	}
	for index, destination := range destinations {
		payload := fmt.Appendf(nil, "flow-%d", index)
		if _, err = conn.WriteToUDPAddrPort(payload, destination); err != nil {
			t.Fatal(err)
		}
		if err = conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
			t.Fatal(err)
		}
		response := make([]byte, 64)
		n, source, readErr := conn.ReadFromUDPAddrPort(response)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if source != destination {
			t.Fatalf("unexpected restored source for flow %d: %s", index, source)
		}
		expectedResponse := append([]byte("udp6-ok:"), payload...)
		if !bytes.Equal(response[:n], expectedResponse) {
			t.Fatalf("unexpected response for flow %d: %q", index, response[:n])
		}
	}
}

func pinCurrentThread(t *testing.T) {
	t.Helper()
	var available unix.CPUSet
	if err := unix.SchedGetaffinity(0, &available); err != nil {
		t.Fatal(err)
	}
	for cpu := 0; cpu < 1024; cpu++ {
		if !available.IsSet(cpu) {
			continue
		}
		var selected unix.CPUSet
		selected.Set(cpu)
		if err := unix.SchedSetaffinity(0, &selected); err != nil {
			t.Fatal(err)
		}
		return
	}
	t.Fatal("current process has no available CPU")
}

func TestSharedNetworkDataPathIntegration(t *testing.T) {
	if os.Getenv("SING_BOX_EBPF_SHARED_INTEGRATION") != "1" {
		t.Skip("set SING_BOX_EBPF_SHARED_INTEGRATION=1 to run the root TC integration test")
	}
	if os.Geteuid() != 0 {
		t.Fatal("shared-network integration test requires root")
	}

	const (
		namespace = "sb-ebpf-test"
		hostLink  = "sbe-host"
		peerLink  = "sbe-peer"
	)
	runIP := func(arguments ...string) {
		t.Helper()
		command := exec.Command("ip", arguments...)
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("ip %s: %v: %s", strings.Join(arguments, " "), err, output)
		}
	}
	_ = exec.Command("ip", "netns", "del", namespace).Run()
	_ = exec.Command("ip", "link", "del", hostLink).Run()
	t.Cleanup(func() {
		_ = exec.Command("ip", "netns", "del", namespace).Run()
		_ = exec.Command("ip", "link", "del", hostLink).Run()
	})
	runIP("netns", "add", namespace)
	runIP("link", "add", hostLink, "type", "veth", "peer", "name", peerLink)
	runIP("link", "set", peerLink, "netns", namespace)
	runIP("address", "add", "192.0.2.1/24", "dev", hostLink)
	runIP("-6", "address", "add", "2001:db8:1::1/64", "dev", hostLink, "nodad")
	runIP("link", "set", hostLink, "up")
	runIP("netns", "exec", namespace, "ip", "link", "set", "lo", "up")
	runIP("netns", "exec", namespace, "ip", "address", "add", "192.0.2.2/24", "dev", peerLink)
	runIP("netns", "exec", namespace, "ip", "-6", "address", "add", "2001:db8:1::2/64", "dev", peerLink, "nodad")
	runIP("netns", "exec", namespace, "ip", "link", "set", peerLink, "up")
	runIP("netns", "exec", namespace, "ip", "route", "add", "default", "via", "192.0.2.1")
	runIP("netns", "exec", namespace, "ip", "-6", "route", "add", "default", "via", "2001:db8:1::1")
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
	tcp6Listener, err := net.ListenTCP("tcp6", &net.TCPAddr{IP: net.IPv6unspecified, Port: int(listenerPort)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tcp6Listener.Close() })
	udp6Listener, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6unspecified, Port: int(listenerPort)})
	if err != nil {
		t.Fatal(err)
	}
	rawUDP6, err := udp6Listener.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var socketControlErr error
	if err = rawUDP6.Control(func(fd uintptr) {
		socketControlErr = unix.SetsockoptInt(int(fd), unix.SOL_IPV6, unix.IPV6_TRANSPARENT, 1)
	}); err != nil {
		t.Fatal(err)
	}
	if socketControlErr != nil {
		t.Fatal(socketControlErr)
	}
	t.Cleanup(func() { _ = udp6Listener.Close() })
	if err = ipv6.NewPacketConn(udp6Listener).SetControlMessage(ipv6.FlagDst, true); err != nil {
		t.Fatal(err)
	}

	redirectPrefix := netip.MustParsePrefix("127.128.0.0/9")
	redirectPrefix6 := netip.MustParsePrefix("fd53:696e:672d:626f::/64")
	routeOwner := &Inbound{}
	routeOwner.localRoutes, err = addLocalRoutes([]netip.Prefix{redirectPrefix, redirectPrefix6})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = routeOwner.removeLocalRoutes() })
	backend, err := ECommon.PrepareSharedNetwork(nil, ECommon.SharedNetworkConfig{
		ListenerPort:         listenerPort,
		EnableTCP:            true,
		EnableUDP:            true,
		DNSMode:              ECommon.DNSModeHijack,
		BypassPrivateAddress: false,
		RedirectIPv4:         redirectPrefix,
		RedirectIPv6:         redirectPrefix6,
		MapCapacity: ECommon.SharedNetworkMapCapacities{
			Proxy:  7,
			Bypass: 7,
		},
		UDPTimeout: 5 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	if err = backend.UpdateHostAddresses([]netip.Addr{
		netip.MustParseAddr("192.0.2.1"),
		netip.MustParseAddr("2001:db8:1::1"),
	}); err != nil {
		t.Fatal(err)
	}
	manager := &sharedTCManager{
		backend:     backend,
		logger:      discardInterfaceLogger{},
		interfaces:  []string{"sbe-not-found", hostLink},
		enableIPv4:  true,
		attachments: make(map[string]*sharedTCAttachment),
	}
	if err = manager.reconcile(); err != nil {
		t.Fatal(err)
	}
	if !manager.enabled || len(manager.attachments) != 1 {
		t.Fatalf("unexpected initial TC state: enabled=%v attachments=%d", manager.enabled, len(manager.attachments))
	}
	t.Cleanup(func() { _ = manager.closeAttachments() })

	attachment := manager.attachments[hostLink]
	if attachment.tcx == nil {
		ingressProgramID := attachment.ingress.Id
		if err = netlink.FilterDel(attachment.ingress); err != nil {
			t.Fatal(err)
		}
		if err = manager.reconcile(); err != nil {
			t.Fatal(err)
		}
		repairedAttachment := manager.attachments[hostLink]
		if repairedAttachment.ingress == nil || repairedAttachment.ingress.Id == 0 {
			t.Fatal("shared-network ingress filter was not restored")
		}
		if repairedAttachment.ingress.Id != ingressProgramID {
			t.Fatalf("shared-network ingress program changed during repair: %d != %d", repairedAttachment.ingress.Id, ingressProgramID)
		}
		runIP("qdisc", "del", "dev", hostLink, "clsact")
		if err = manager.reconcile(); err != nil {
			t.Fatal(err)
		}
	} else {
		repaired, repairErr := backend.RepairTCX(attachment.tcx, attachment.interfaceIndex)
		if repairErr != nil {
			t.Fatal(repairErr)
		}
		if repaired {
			t.Fatal("healthy shared-network TCX attachment was replaced")
		}
	}
	if err = os.WriteFile(sharedRouteLocalnetPath(hostLink), []byte("0"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err = manager.reconcile(); err != nil {
		t.Fatal(err)
	}
	routeLocalnet, err := os.ReadFile(sharedRouteLocalnetPath(hostLink))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(routeLocalnet)) != "1" {
		t.Fatalf("route_localnet was not repaired: %q", routeLocalnet)
	}
	tcpPayload := bytes.Repeat([]byte("shared-network-gso-path"), 16384)
	tcpResult := make(chan error, 1)
	go func() {
		_ = tcpListener.SetDeadline(time.Now().Add(5 * time.Second))
		conn, acceptErr := tcpListener.AcceptTCP()
		if acceptErr != nil {
			tcpResult <- acceptErr
			return
		}
		defer conn.Close()
		client := conn.RemoteAddr().(*net.TCPAddr).AddrPort()
		tokenDestination := conn.LocalAddr().(*net.TCPAddr).AddrPort()
		original, flow, lookupErr := backend.LookupFlow(ECommon.ProtocolTCP, client, tokenDestination)
		if lookupErr != nil {
			tcpResult <- lookupErr
			return
		}
		defer backend.ReleaseFlow(flow)
		if original.Destination != netip.MustParseAddrPort("10.0.0.1:18080") {
			tcpResult <- &unexpectedDestinationError{original.Destination}
			return
		}
		payload := make([]byte, len(tcpPayload))
		if _, readErr := io.ReadFull(conn, payload); readErr != nil {
			tcpResult <- readErr
			return
		}
		if !bytes.Equal(payload, tcpPayload) {
			tcpResult <- fmt.Errorf("unexpected intercepted payload length: %d", len(payload))
			return
		}
		_, writeErr := conn.Write([]byte("tcp-ok"))
		tcpResult <- writeErr
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tcpCommand := exec.CommandContext(ctx, "ip", "netns", "exec", namespace, "nc", "-w", "3", "10.0.0.1", "18080")
	tcpCommand.Stdin = bytes.NewReader(tcpPayload)
	tcpOutput, err := tcpCommand.Output()
	if err != nil {
		t.Fatalf("TCP client: %v", err)
	}
	if string(tcpOutput) != "tcp-ok" {
		t.Fatalf("unexpected TCP response: %q", tcpOutput)
	}
	if err = <-tcpResult; err != nil {
		t.Fatal(err)
	}

	tcp6Result := make(chan error, 1)
	go func() {
		_ = tcp6Listener.SetDeadline(time.Now().Add(5 * time.Second))
		conn, acceptErr := tcp6Listener.AcceptTCP()
		if acceptErr != nil {
			tcp6Result <- acceptErr
			return
		}
		defer conn.Close()
		client := conn.RemoteAddr().(*net.TCPAddr).AddrPort()
		tokenDestination := conn.LocalAddr().(*net.TCPAddr).AddrPort()
		original, flow, lookupErr := backend.LookupFlow(ECommon.ProtocolTCP, client, tokenDestination)
		if lookupErr != nil {
			tcp6Result <- lookupErr
			return
		}
		defer backend.ReleaseFlow(flow)
		if original.Destination != netip.MustParseAddrPort("[2001:4860:4860::8888]:18081") {
			tcp6Result <- &unexpectedDestinationError{original.Destination}
			return
		}
		_, writeErr := conn.Write([]byte("tcp6-ok"))
		tcp6Result <- writeErr
	}()
	tcp6Context, tcp6Cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer tcp6Cancel()
	tcp6Command := exec.CommandContext(
		tcp6Context,
		"ip", "netns", "exec", namespace,
		"nc", "-6", "-w", "3", "2001:4860:4860::8888", "18081",
	)
	tcp6Output, err := tcp6Command.Output()
	if err != nil {
		t.Fatalf("IPv6 TCP client: %v", err)
	}
	if string(tcp6Output) != "tcp6-ok" {
		t.Fatalf("unexpected IPv6 TCP response: %q", tcp6Output)
	}
	if err = <-tcp6Result; err != nil {
		t.Fatal(err)
	}

	udpResult := make(chan error, 1)
	go func() {
		_ = udpListener.SetReadDeadline(time.Now().Add(5 * time.Second))
		payload := make([]byte, 64)
		oob := make([]byte, 256)
		n, oobN, _, client, readErr := udpListener.ReadMsgUDPAddrPort(payload, oob)
		if readErr != nil {
			udpResult <- readErr
			return
		}
		tokenAddress, parseErr := redirectAddressFromOOB(oob[:oobN])
		if parseErr != nil {
			udpResult <- parseErr
			return
		}
		tokenDestination := netip.AddrPortFrom(tokenAddress, listenerPort)
		original, flow, lookupErr := backend.LookupFlow(ECommon.ProtocolUDP, client, tokenDestination)
		if lookupErr != nil {
			udpResult <- lookupErr
			return
		}
		defer backend.ReleaseFlow(flow)
		if original.Destination != netip.MustParseAddrPort("192.0.2.1:53") {
			udpResult <- &unexpectedDestinationError{original.Destination}
			return
		}
		controlMessage := (&ipv4.ControlMessage{Src: net.IP(tokenAddress.AsSlice())}).Marshal()
		_, _, writeErr := udpListener.WriteMsgUDPAddrPort(append([]byte("udp-ok:"), payload[:n]...), controlMessage, client)
		udpResult <- writeErr
	}()
	udpCommand := exec.CommandContext(ctx, "ip", "netns", "exec", namespace, "nc", "-u", "-w", "3", "192.0.2.1", "53")
	udpCommand.Stdin = strings.NewReader("dns")
	udpOutput, err := udpCommand.Output()
	if err != nil {
		t.Fatalf("UDP client: %v", err)
	}
	if string(udpOutput) != "udp-ok:dns" {
		t.Fatalf("unexpected UDP response: %q", udpOutput)
	}
	if err = <-udpResult; err != nil {
		t.Fatal(err)
	}

	udp6Result := make(chan error, 1)
	go func() {
		destinations := []netip.AddrPort{
			netip.MustParseAddrPort("[2001:db8:1::1]:53"),
			netip.MustParseAddrPort("[2001:4860:4860::8888]:5353"),
			netip.MustParseAddrPort("[2001:db8:1::1]:53"),
		}
		for _, expectedDestination := range destinations {
			_ = udp6Listener.SetReadDeadline(time.Now().Add(5 * time.Second))
			payload := make([]byte, 64)
			oob := make([]byte, 256)
			n, oobN, _, client, readErr := udp6Listener.ReadMsgUDPAddrPort(payload, oob)
			if readErr != nil {
				udp6Result <- readErr
				return
			}
			tokenAddress, parseErr := redirectAddressFromOOB(oob[:oobN])
			if parseErr != nil {
				udp6Result <- parseErr
				return
			}
			tokenDestination := netip.AddrPortFrom(tokenAddress, listenerPort)
			original, flow, lookupErr := backend.LookupFlow(ECommon.ProtocolUDP, client, tokenDestination)
			if lookupErr != nil {
				udp6Result <- lookupErr
				return
			}
			defer backend.ReleaseFlow(flow)
			if original.Destination != expectedDestination {
				udp6Result <- &unexpectedDestinationError{original.Destination}
				return
			}
			controlMessage := (&ipv6.ControlMessage{Src: net.IP(tokenAddress.AsSlice())}).Marshal()
			if _, _, writeErr := udp6Listener.WriteMsgUDPAddrPort(
				append([]byte("udp6-ok:"), payload[:n]...),
				controlMessage,
				client,
			); writeErr != nil {
				udp6Result <- writeErr
				return
			}
		}
		udp6Result <- nil
	}()
	udp6Context, udp6Cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer udp6Cancel()
	udp6Command := exec.CommandContext(
		udp6Context,
		"ip", "netns", "exec", namespace, os.Args[0],
		"-test.run=^TestSharedNetworkUDPClientHelper$",
	)
	udp6Command.Env = append(os.Environ(), sharedNetworkUDPClientHelperEnv+"=1")
	udp6Output, err := udp6Command.CombinedOutput()
	if err != nil {
		serverErr := <-udp6Result
		t.Fatalf("IPv6 UDP client: %v: %s; server: %v", err, udp6Output, serverErr)
	}
	if err = <-udp6Result; err != nil {
		t.Fatal(err)
	}

	dhcpListener, err := net.ListenUDP("udp4", &net.UDPAddr{
		IP:   net.ParseIP("192.0.2.1"),
		Port: 67,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer dhcpListener.Close()
	dhcpResult := make(chan error, 1)
	go func() {
		_ = dhcpListener.SetDeadline(time.Now().Add(5 * time.Second))
		payload := make([]byte, 64)
		n, client, readErr := dhcpListener.ReadFromUDPAddrPort(payload)
		if readErr != nil {
			dhcpResult <- readErr
			return
		}
		_, writeErr := dhcpListener.WriteToUDPAddrPort(append([]byte("dhcp-ok:"), payload[:n]...), client)
		dhcpResult <- writeErr
	}()
	dhcpContext, dhcpCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer dhcpCancel()
	dhcpCommand := exec.CommandContext(
		dhcpContext,
		"ip", "netns", "exec", namespace,
		"nc", "-u", "-p", "68", "-w", "2", "192.0.2.1", "67",
	)
	dhcpCommand.Stdin = strings.NewReader("discover")
	dhcpOutput, err := dhcpCommand.Output()
	if err != nil {
		t.Fatalf("DHCP client: %v", err)
	}
	if string(dhcpOutput) != "dhcp-ok:discover" {
		t.Fatalf("unexpected DHCP response: %q", dhcpOutput)
	}
	if err = <-dhcpResult; err != nil {
		t.Fatal(err)
	}

	mapFullAccept := make(chan error, 1)
	go func() {
		_ = tcpListener.SetDeadline(time.Now().Add(2 * time.Second))
		conn, acceptErr := tcpListener.AcceptTCP()
		if acceptErr == nil {
			_ = conn.Close()
		}
		mapFullAccept <- acceptErr
	}()
	mapFullContext, mapFullCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer mapFullCancel()
	mapFullCommand := exec.CommandContext(
		mapFullContext,
		"ip", "netns", "exec", namespace,
		"nc", "-w", "1", "9.9.9.9", "19090",
	)
	_ = mapFullCommand.Run()
	acceptErr := <-mapFullAccept
	if acceptErr == nil {
		t.Fatal("shared-network listener accepted a flow after its maps reached capacity")
	}
	if networkError, isNetworkError := acceptErr.(net.Error); !isNetworkError || !networkError.Timeout() {
		t.Fatalf("wait for map-capacity rejection: %v", acceptErr)
	}
	time.Sleep(time.Millisecond)
	sweepResult, err := backend.SweepOrphanedFlows(time.Nanosecond, sharedFlowFallbackScanBudget)
	if err != nil {
		t.Fatal(err)
	}
	if sweepResult.Removed == 0 {
		t.Fatal("shared-network map pressure sweep did not release orphaned flows")
	}
	recoveryAccept := make(chan error, 1)
	go func() {
		_ = tcpListener.SetDeadline(time.Now().Add(5 * time.Second))
		conn, acceptErr := tcpListener.AcceptTCP()
		if acceptErr != nil {
			recoveryAccept <- acceptErr
			return
		}
		defer conn.Close()
		client := conn.RemoteAddr().(*net.TCPAddr).AddrPort()
		tokenDestination := conn.LocalAddr().(*net.TCPAddr).AddrPort()
		original, flow, lookupErr := backend.LookupFlow(ECommon.ProtocolTCP, client, tokenDestination)
		if lookupErr == nil {
			defer backend.ReleaseFlow(flow)
		}
		if lookupErr == nil && original.Destination != netip.MustParseAddrPort("9.9.9.9:19090") {
			lookupErr = &unexpectedDestinationError{original.Destination}
		}
		recoveryAccept <- lookupErr
	}()
	recoveryContext, recoveryCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer recoveryCancel()
	recoveryCommand := exec.CommandContext(
		recoveryContext,
		"ip", "netns", "exec", namespace,
		"nc", "-w", "3", "9.9.9.9", "19090",
	)
	_ = recoveryCommand.Run()
	if err = <-recoveryAccept; err != nil {
		t.Fatal("shared-network interception did not recover after map pressure cleanup: ", err)
	}

	runIP("link", "del", hostLink)
	if err = manager.reconcile(); err != nil {
		t.Fatal(err)
	}
	if manager.enabled || len(manager.attachments) != 0 {
		t.Fatalf("TC state was retained after interface removal: enabled=%v attachments=%d", manager.enabled, len(manager.attachments))
	}
	runIP("link", "add", hostLink, "type", "dummy")
	runIP("link", "set", hostLink, "up")
	if err = manager.reconcile(); err != nil {
		t.Fatal(err)
	}
	if !manager.enabled || len(manager.attachments) != 1 {
		t.Fatalf("TC state was not restored after interface recreation: enabled=%v attachments=%d", manager.enabled, len(manager.attachments))
	}
}

type discardInterfaceLogger struct{}

func (discardInterfaceLogger) Debug(...any) {}
func (discardInterfaceLogger) Info(...any)  {}
func (discardInterfaceLogger) Warn(...any)  {}

type unexpectedDestinationError struct {
	destination netip.AddrPort
}

func (e *unexpectedDestinationError) Error() string {
	return "unexpected original destination: " + e.destination.String()
}
