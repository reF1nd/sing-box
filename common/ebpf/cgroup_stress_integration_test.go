//go:build with_ebpf && (linux || android) && ebpf_integration

package ebpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/net/ipv4"
)

const (
	integrationStressEnv                    = "SING_BOX_EBPF_STRESS"
	integrationStressHelperEnv              = "SING_BOX_EBPF_STRESS_HELPER"
	integrationStressTCPCountEnv            = "SING_BOX_EBPF_STRESS_TCP_COUNT"
	integrationStressUDPConnectedCountEnv   = "SING_BOX_EBPF_STRESS_UDP_CONNECTED_COUNT"
	integrationStressUDPUnconnectedCountEnv = "SING_BOX_EBPF_STRESS_UDP_UNCONNECTED_COUNT"
	integrationStressWorkersEnv             = "SING_BOX_EBPF_STRESS_WORKERS"
	integrationStressListenerPort           = "SING_BOX_EBPF_STRESS_LISTENER_PORT"
)

const (
	defaultStressTCPCount            = 10000
	defaultStressUDPConnectedCount   = 10000
	defaultStressUDPUnconnectedCount = 10000
	defaultStressWorkers             = 128
)

func TestCgroupBackendTrafficStressIntegration(t *testing.T) {
	requireEBPFIntegration(t, "stress local TCP and UDP interception")
	if os.Getenv(integrationStressEnv) != "1" {
		t.Skip("set " + integrationStressEnv + "=1 to run the traffic stress test")
	}
	tcpCount := stressEnvironmentInt(t, integrationStressTCPCountEnv, defaultStressTCPCount)
	udpConnectedCount := stressEnvironmentInt(t, integrationStressUDPConnectedCountEnv, defaultStressUDPConnectedCount)
	udpUnconnectedCount := stressEnvironmentInt(t, integrationStressUDPUnconnectedCountEnv, defaultStressUDPUnconnectedCount)
	workers := stressEnvironmentInt(t, integrationStressWorkersEnv, defaultStressWorkers)
	cgroupMount, err := DetectCgroup2Mount()
	if err != nil {
		t.Fatal(err)
	}
	cgroupPath, err := os.MkdirTemp(cgroupMount, "sing-box-ebpf-stress-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err = os.Remove(cgroupPath); err != nil {
			t.Errorf("remove stress-test cgroup: %v", err)
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

	backend, err := PrepareCgroup(CgroupConfig{
		Path:         cgroupPath,
		EnableTCP:    true,
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
		if err = backend.Close(); err != nil {
			t.Errorf("close stress-test backend: %v", err)
		}
	})
	if err = backend.LoadPrograms(listenerPort); err != nil {
		t.Fatal(err)
	}
	if err = backend.Attach(); err != nil {
		t.Fatal(err)
	}

	readyReader, readyWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer readyWriter.Close()
	var helperOutput bytes.Buffer
	helper := exec.Command(os.Args[0], "-test.run=^TestCgroupBackendTrafficStressHelper$")
	helper.Env = append(os.Environ(),
		integrationStressHelperEnv+"=1",
		integrationStressTCPCountEnv+"="+strconv.Itoa(tcpCount),
		integrationStressUDPConnectedCountEnv+"="+strconv.Itoa(udpConnectedCount),
		integrationStressUDPUnconnectedCountEnv+"="+strconv.Itoa(udpUnconnectedCount),
		integrationStressWorkersEnv+"="+strconv.Itoa(workers),
		integrationStressListenerPort+"="+strconv.Itoa(int(listenerPort)),
	)
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
	if err = os.WriteFile(filepath.Join(cgroupPath, "cgroup.procs"), []byte(strconv.Itoa(helper.Process.Pid)), 0); err != nil {
		t.Fatal(err)
	}
	if _, err = readyWriter.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	if err = readyWriter.Close(); err != nil {
		t.Fatal(err)
	}

	tcpStarted := time.Now()
	serveStressTCP(t, backend, tcpListener, tcpCount)
	tcpDuration := time.Since(tcpStarted)
	udpConnectedStarted := time.Now()
	serveStressUDP(t, backend, udpListener, udpConnectedCount, true)
	udpConnectedDuration := time.Since(udpConnectedStarted)
	udpUnconnectedStarted := time.Now()
	unconnectedRedirects := serveStressUDP(t, backend, udpListener, udpUnconnectedCount, false)
	udpUnconnectedDuration := time.Since(udpUnconnectedStarted)
	if err = helper.Wait(); err != nil {
		helperWaited = true
		t.Fatalf("stress helper: %v: %s", err, helperOutput.Bytes())
	}
	helperWaited = true
	for _, redirect := range unconnectedRedirects {
		if err = backend.DeleteRedirect(ProtocolUDP, redirect); err != nil {
			t.Fatalf("delete unconnected UDP redirect %v: %v", redirect, err)
		}
	}

	redirectEntries, err := countMapEntriesForTest(
		backend.udpRedirectMapFD,
		unsafe.Sizeof(listenerLookupKey{}),
		backend.mapCapacity.UDPRedirect,
	)
	if err != nil {
		t.Fatal(err)
	}
	if usesSocketReleaseForTest(backend) && redirectEntries != 0 {
		t.Fatalf("connected UDP redirects survived socket release: %d", redirectEntries)
	}
	t.Logf(
		"TCP short connections: count=%d workers=%d elapsed=%s rate=%.0f connections/s",
		tcpCount,
		workers,
		tcpDuration,
		float64(tcpCount)/tcpDuration.Seconds(),
	)
	t.Logf(
		"UDP connected round trips: count=%d workers=%d elapsed=%s rate=%.0f packets/s cleanup=%s remaining_redirects=%d",
		udpConnectedCount,
		workers,
		udpConnectedDuration,
		float64(udpConnectedCount)/udpConnectedDuration.Seconds(),
		backend.UDPCleanupMode(),
		redirectEntries,
	)
	t.Logf(
		"UDP unconnected round trips: count=%d workers=%d elapsed=%s rate=%.0f packets/s remaining_redirects=%d",
		udpUnconnectedCount,
		workers,
		udpUnconnectedDuration,
		float64(udpUnconnectedCount)/udpUnconnectedDuration.Seconds(),
		redirectEntries,
	)
}

func serveStressTCP(t *testing.T, backend *CgroupBackend, listener *net.TCPListener, count int) {
	t.Helper()
	if err := listener.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < count; index++ {
		connection, err := listener.AcceptTCP()
		if err != nil {
			t.Fatalf("accept stress TCP connection %d: %v", index, err)
		}
		var payload [8]byte
		_, readErr := io.ReadFull(connection, payload[:])
		redirectDestination := connection.LocalAddr().(*net.TCPAddr).AddrPort()
		closeErr := connection.Close()
		if readErr != nil {
			t.Fatalf("read stress TCP connection %d: %v", index, readErr)
		}
		if closeErr != nil {
			t.Fatal(closeErr)
		}
		original, lookupErr := backend.TakeOriginal(ProtocolTCP, redirectDestination)
		if lookupErr != nil {
			t.Fatalf("lookup stress TCP original destination %d: %v", index, lookupErr)
		}
		if original.Destination != netip.MustParseAddrPort("198.51.100.10:443") {
			t.Fatalf("unexpected stress TCP original destination %d: %v", index, original.Destination)
		}
	}
}

func serveStressUDP(
	t *testing.T,
	backend *CgroupBackend,
	listener *net.UDPConn,
	count int,
	connected bool,
) []netip.AddrPort {
	t.Helper()
	if err := listener.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 8)
	oob := make([]byte, 128)
	redirects := make([]netip.AddrPort, 0, count)
	for index := 0; index < count; index++ {
		n, oobN, _, client, err := listener.ReadMsgUDPAddrPort(payload, oob)
		if err != nil {
			t.Fatalf("read stress UDP packet %d: %v", index, err)
		}
		if n != len(payload) {
			t.Fatalf("unexpected stress UDP payload size %d: %d", index, n)
		}
		var controlMessage ipv4.ControlMessage
		if err = controlMessage.Parse(oob[:oobN]); err != nil {
			t.Fatalf("parse stress UDP packet info %d: %v", index, err)
		}
		token, loaded := netip.AddrFromSlice(controlMessage.Dst)
		if !loaded {
			t.Fatalf("invalid stress UDP token %d: %v", index, controlMessage.Dst)
		}
		token = token.Unmap()
		redirectDestination := netip.AddrPortFrom(token, uint16(listener.LocalAddr().(*net.UDPAddr).Port))
		original, lookupErr := backend.LookupOriginal(ProtocolUDP, redirectDestination)
		if lookupErr != nil {
			t.Fatalf("lookup stress UDP original destination %d: %v", index, lookupErr)
		}
		if original.Destination != netip.MustParseAddrPort("198.51.100.20:5353") || original.ConnectedUDP != connected {
			t.Fatalf("unexpected stress UDP original destination %d: %+v", index, original)
		}
		if !connected {
			redirects = append(redirects, redirectDestination)
		}
		replyOOB := (&ipv4.ControlMessage{Src: net.IP(token.AsSlice())}).Marshal()
		if _, _, err = listener.WriteMsgUDPAddrPort(payload[:n], replyOOB, client); err != nil {
			t.Fatalf("write stress UDP reply %d: %v", index, err)
		}
	}
	return redirects
}

func TestCgroupBackendTrafficStressHelper(t *testing.T) {
	if os.Getenv(integrationStressHelperEnv) != "1" {
		t.Skip("cgroup traffic stress helper")
	}
	tcpCount := stressEnvironmentInt(t, integrationStressTCPCountEnv, defaultStressTCPCount)
	udpConnectedCount := stressEnvironmentInt(t, integrationStressUDPConnectedCountEnv, defaultStressUDPConnectedCount)
	udpUnconnectedCount := stressEnvironmentInt(t, integrationStressUDPUnconnectedCountEnv, defaultStressUDPUnconnectedCount)
	workers := stressEnvironmentInt(t, integrationStressWorkersEnv, defaultStressWorkers)
	listenerPort := stressEnvironmentInt(t, integrationStressListenerPort, 0)
	if listenerPort <= 0 || listenerPort > 65535 {
		t.Fatal("invalid stress listener port")
	}
	readyPipe := os.NewFile(3, "cgroup-ready")
	if readyPipe == nil {
		t.Fatal("missing cgroup ready pipe")
	}
	defer readyPipe.Close()
	if _, err := io.ReadFull(readyPipe, make([]byte, 1)); err != nil {
		t.Fatal(err)
	}

	runStressWorkers(t, tcpCount, workers, func(index int) error {
		connection, err := net.DialTimeout("tcp4", "198.51.100.10:443", 10*time.Second)
		if err != nil {
			return err
		}
		var payload [8]byte
		binary.NativeEndian.PutUint64(payload[:], uint64(index))
		_, writeErr := connection.Write(payload[:])
		return errors.Join(writeErr, connection.Close())
	})
	runStressWorkers(t, udpConnectedCount, workers, func(index int) error {
		connection, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(netip.MustParseAddrPort("198.51.100.20:5353")))
		if err != nil {
			return err
		}
		defer connection.Close()
		if err = connection.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
			return err
		}
		var payload [8]byte
		binary.NativeEndian.PutUint64(payload[:], uint64(index))
		if _, err = connection.Write(payload[:]); err != nil {
			return err
		}
		var reply [8]byte
		n, source, err := connection.ReadFromUDPAddrPort(reply[:])
		if err != nil {
			return err
		}
		if n != len(reply) || reply != payload {
			return fmt.Errorf("unexpected UDP reply payload for operation %d", index)
		}
		if expected := netip.MustParseAddrPort("198.51.100.20:5353"); source != expected {
			return fmt.Errorf("UDP reply source was not restored: got %v, expected %v", source, expected)
		}
		return nil
	})
	runStressWorkers(t, udpUnconnectedCount, workers, func(index int) error {
		connection, err := net.ListenUDP("udp4", nil)
		if err != nil {
			return err
		}
		defer connection.Close()
		if err = connection.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
			return err
		}
		var payload [8]byte
		binary.NativeEndian.PutUint64(payload[:], uint64(index))
		destination := netip.MustParseAddrPort("198.51.100.20:5353")
		if _, err = connection.WriteToUDPAddrPort(payload[:], destination); err != nil {
			return err
		}
		var reply [8]byte
		n, source, err := connection.ReadFromUDPAddrPort(reply[:])
		if err != nil {
			return err
		}
		if n != len(reply) || reply != payload {
			return fmt.Errorf("unexpected unconnected UDP reply payload for operation %d", index)
		}
		if source != destination {
			return fmt.Errorf("unconnected UDP reply source was not restored: got %v, expected %v", source, destination)
		}
		return nil
	})
}

func runStressWorkers(t *testing.T, count int, workers int, operation func(index int) error) {
	t.Helper()
	jobs := make(chan int)
	errorsChannel := make(chan error, workers)
	var waitGroup sync.WaitGroup
	var failed atomic.Bool
	for range workers {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			for index := range jobs {
				if failed.Load() {
					continue
				}
				if err := operation(index); err != nil {
					failed.Store(true)
					select {
					case errorsChannel <- err:
					default:
					}
				}
			}
		}()
	}
	for index := 0; index < count; index++ {
		jobs <- index
	}
	close(jobs)
	waitGroup.Wait()
	close(errorsChannel)
	if err := <-errorsChannel; err != nil {
		t.Fatal(err)
	}
}

func stressEnvironmentInt(t *testing.T, name string, fallback int) int {
	t.Helper()
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		t.Fatalf("invalid %s: %q", name, value)
	}
	return parsed
}
