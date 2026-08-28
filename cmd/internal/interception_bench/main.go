package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	tcpShortMarker    = 1
	tcpUploadMarker   = 2
	tcpDownloadMarker = 3
)

type options struct {
	mode           string
	listen         string
	target         string
	scenarios      string
	duration       time.Duration
	warmup         time.Duration
	concurrency    int
	tcpPayloadSize int
	udpPayloadSize int
	dialTimeout    time.Duration
}

type report struct {
	Target         string        `json:"target"`
	Duration       string        `json:"duration"`
	Warmup         string        `json:"warmup"`
	Concurrency    int           `json:"concurrency"`
	TCPPayloadSize int           `json:"tcp_payload_size"`
	UDPPayloadSize int           `json:"udp_payload_size"`
	GOOS           string        `json:"goos"`
	GOARCH         string        `json:"goarch"`
	CPUs           int           `json:"cpus"`
	Results        []measurement `json:"results"`
}

type measurement struct {
	Scenario   string  `json:"scenario"`
	Seconds    float64 `json:"seconds"`
	Operations uint64  `json:"operations,omitempty"`
	Bytes      uint64  `json:"bytes,omitempty"`
	Rate       float64 `json:"rate"`
	Unit       string  `json:"unit"`
	Errors     uint64  `json:"errors"`
}

type counters struct {
	operations atomic.Uint64
	bytes      atomic.Uint64
	errors     atomic.Uint64
}

func main() {
	options := parseOptions()
	var err error
	switch options.mode {
	case "server":
		err = runServer(options.listen)
	case "client":
		err = runClient(options)
	default:
		err = fmt.Errorf("unknown mode %q", options.mode)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func parseOptions() options {
	var options options
	flag.StringVar(&options.mode, "mode", "client", "client or server")
	flag.StringVar(&options.listen, "listen", ":5201", "server TCP/UDP listen address")
	flag.StringVar(&options.target, "target", "", "client target address")
	flag.StringVar(
		&options.scenarios,
		"scenario",
		"all",
		"all or a comma-separated list of tcp-short,tcp-upload,tcp-download,udp-pps,udp-unconnected-pps,udp-churn",
	)
	flag.DurationVar(&options.duration, "duration", 10*time.Second, "measurement duration per scenario")
	flag.DurationVar(&options.warmup, "warmup", 2*time.Second, "warm-up duration per scenario")
	flag.IntVar(&options.concurrency, "concurrency", 16, "parallel connections or UDP flows")
	flag.IntVar(&options.tcpPayloadSize, "tcp-payload-size", 32768, "TCP upload frame size")
	flag.IntVar(&options.udpPayloadSize, "udp-payload-size", 1200, "UDP datagram size")
	flag.DurationVar(&options.dialTimeout, "dial-timeout", 3*time.Second, "per-connection dial timeout")
	flag.Parse()
	return options
}

func runServer(listenAddress string) error {
	tcpListener, err := net.Listen("tcp", listenAddress)
	if err != nil {
		return fmt.Errorf("listen TCP: %w", err)
	}
	defer tcpListener.Close()
	udpListener, err := net.ListenPacket("udp", listenAddress)
	if err != nil {
		return fmt.Errorf("listen UDP: %w", err)
	}
	defer udpListener.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go serveTCP(ctx, tcpListener)
	go serveUDP(ctx, udpListener)
	fmt.Fprintf(os.Stderr, "interception benchmark server listening at %s (TCP/UDP)\n", listenAddress)
	<-ctx.Done()
	return nil
}

func serveTCP(ctx context.Context, listener net.Listener) {
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	for {
		connection, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}
		go handleTCP(connection)
	}
}

func handleTCP(connection net.Conn) {
	defer connection.Close()
	var marker [1]byte
	if _, err := io.ReadFull(connection, marker[:]); err != nil {
		return
	}
	switch marker[0] {
	case tcpShortMarker:
		_, _ = connection.Write(marker[:])
	case tcpUploadMarker:
		var count uint64
		var frameHeader [4]byte
		for {
			if _, err := io.ReadFull(connection, frameHeader[:]); err != nil {
				return
			}
			frameLength := binary.BigEndian.Uint32(frameHeader[:])
			if frameLength == 0 {
				break
			}
			if frameLength > 65507 {
				return
			}
			if _, err := io.CopyN(io.Discard, connection, int64(frameLength)); err != nil {
				return
			}
			count += uint64(frameLength)
		}
		var response [8]byte
		binary.BigEndian.PutUint64(response[:], count)
		_, _ = connection.Write(response[:])
	case tcpDownloadMarker:
		payload := make([]byte, 64*1024)
		for {
			if _, err := connection.Write(payload); err != nil {
				return
			}
		}
	}
}

func serveUDP(ctx context.Context, listener net.PacketConn) {
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	buffer := make([]byte, 64*1024)
	for {
		n, source, err := listener.ReadFrom(buffer)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}
		if _, err = listener.WriteTo(buffer[:n], source); err != nil && ctx.Err() != nil {
			return
		}
	}
}

func runClient(options options) error {
	if options.target == "" {
		return errors.New("missing -target")
	}
	if options.duration <= 0 || options.warmup < 0 {
		return errors.New("duration must be positive and warmup must not be negative")
	}
	if options.concurrency <= 0 {
		return errors.New("concurrency must be positive")
	}
	if options.tcpPayloadSize < 1 || options.tcpPayloadSize > 1<<20 {
		return errors.New("tcp-payload-size must be between 1 and 1048576")
	}
	if options.udpPayloadSize < 1 || options.udpPayloadSize > 65507 {
		return errors.New("udp-payload-size must be between 1 and 65507")
	}
	scenarios, err := parseScenarios(options.scenarios)
	if err != nil {
		return err
	}
	report := report{
		Target:         options.target,
		Duration:       options.duration.String(),
		Warmup:         options.warmup.String(),
		Concurrency:    options.concurrency,
		TCPPayloadSize: options.tcpPayloadSize,
		UDPPayloadSize: options.udpPayloadSize,
		GOOS:           runtime.GOOS,
		GOARCH:         runtime.GOARCH,
		CPUs:           runtime.NumCPU(),
	}
	for _, scenario := range scenarios {
		if options.warmup > 0 {
			if _, err = measureScenario(options, scenario, options.warmup); err != nil {
				return fmt.Errorf("warm up %s: %w", scenario, err)
			}
		}
		result, err := measureScenario(options, scenario, options.duration)
		if err != nil {
			return fmt.Errorf("measure %s: %w", scenario, err)
		}
		report.Results = append(report.Results, result)
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

func parseScenarios(value string) ([]string, error) {
	if value == "all" {
		return []string{"tcp-short", "tcp-upload", "tcp-download", "udp-pps", "udp-unconnected-pps", "udp-churn"}, nil
	}
	seen := make(map[string]bool)
	var scenarios []string
	for scenario := range strings.SplitSeq(value, ",") {
		scenario = strings.TrimSpace(scenario)
		switch scenario {
		case "tcp-short", "tcp-upload", "tcp-download", "udp-pps", "udp-unconnected-pps", "udp-churn":
		default:
			return nil, fmt.Errorf("unknown scenario %q", scenario)
		}
		if !seen[scenario] {
			seen[scenario] = true
			scenarios = append(scenarios, scenario)
		}
	}
	if len(scenarios) == 0 {
		return nil, errors.New("missing scenario")
	}
	return scenarios, nil
}

func measureScenario(options options, scenario string, duration time.Duration) (measurement, error) {
	startedAt := time.Now()
	deadline := startedAt.Add(duration)
	var result counters
	var err error
	switch scenario {
	case "tcp-short":
		err = measureTCPShort(options, deadline, &result)
	case "tcp-upload":
		err = measureTCPUpload(options, deadline, &result)
	case "tcp-download":
		err = measureTCPDownload(options, deadline, &result)
	case "udp-pps":
		err = measureConnectedUDP(options, deadline, &result)
	case "udp-unconnected-pps":
		err = measureUnconnectedUDP(options, deadline, &result)
	case "udp-churn":
		err = measureUDPChurn(options, deadline, &result)
	}
	elapsed := time.Since(startedAt)
	measurement := measurement{
		Scenario:   scenario,
		Seconds:    elapsed.Seconds(),
		Operations: result.operations.Load(),
		Bytes:      result.bytes.Load(),
		Errors:     result.errors.Load(),
	}
	if scenario == "tcp-upload" || scenario == "tcp-download" {
		measurement.Rate = float64(measurement.Bytes*8) / elapsed.Seconds()
		measurement.Unit = "bit/s"
	} else {
		measurement.Rate = float64(measurement.Operations) / elapsed.Seconds()
		measurement.Unit = "op/s"
	}
	return measurement, err
}

func measureTCPShort(options options, deadline time.Time, result *counters) error {
	return runWorkers(options.concurrency, func() {
		for time.Now().Before(deadline) {
			connection, err := net.DialTimeout("tcp", options.target, remainingTimeout(deadline, options.dialTimeout))
			if err != nil {
				if !isTimeout(err) && time.Now().Before(deadline) {
					result.errors.Add(1)
				}
				continue
			}
			_ = connection.SetDeadline(deadline)
			var payload [1]byte
			payload[0] = tcpShortMarker
			_, writeErr := connection.Write(payload[:])
			_, readErr := io.ReadFull(connection, payload[:])
			_ = connection.Close()
			if writeErr != nil || readErr != nil || payload[0] != tcpShortMarker {
				unexpectedResponse := writeErr == nil && readErr == nil && payload[0] != tcpShortMarker
				unexpectedError := writeErr != nil && !isTimeout(writeErr) || readErr != nil && !isTimeout(readErr)
				if time.Now().Before(deadline) && (unexpectedResponse || unexpectedError) {
					result.errors.Add(1)
				}
				continue
			}
			result.operations.Add(1)
		}
	})
}

func measureTCPUpload(options options, deadline time.Time, result *counters) error {
	return runWorkers(options.concurrency, func() {
		address, err := net.ResolveTCPAddr("tcp", options.target)
		if err != nil {
			result.errors.Add(1)
			return
		}
		connection, err := net.DialTCP("tcp", nil, address)
		if err != nil {
			result.errors.Add(1)
			return
		}
		defer connection.Close()
		_ = connection.SetDeadline(deadline.Add(options.dialTimeout))
		if _, err = connection.Write([]byte{tcpUploadMarker}); err != nil {
			result.errors.Add(1)
			return
		}
		frame := make([]byte, 4+options.tcpPayloadSize)
		binary.BigEndian.PutUint32(frame[:4], uint32(options.tcpPayloadSize))
		for time.Now().Before(deadline) {
			if _, err = connection.Write(frame); err != nil {
				break
			}
		}
		var finalFrame [4]byte
		if _, err = connection.Write(finalFrame[:]); err != nil {
			result.errors.Add(1)
			return
		}
		var response [8]byte
		if _, err = io.ReadFull(connection, response[:]); err != nil {
			result.errors.Add(1)
			return
		}
		result.bytes.Add(binary.BigEndian.Uint64(response[:]))
	})
}

func measureTCPDownload(options options, deadline time.Time, result *counters) error {
	return runWorkers(options.concurrency, func() {
		connection, err := net.DialTimeout("tcp", options.target, remainingTimeout(deadline, options.dialTimeout))
		if err != nil {
			result.errors.Add(1)
			return
		}
		defer connection.Close()
		_ = connection.SetDeadline(deadline)
		if _, err = connection.Write([]byte{tcpDownloadMarker}); err != nil {
			result.errors.Add(1)
			return
		}
		payload := make([]byte, 64*1024)
		var received uint64
		for {
			n, readErr := connection.Read(payload)
			received += uint64(n)
			if readErr != nil {
				if !isTimeout(readErr) && time.Now().Before(deadline) {
					result.errors.Add(1)
				}
				break
			}
		}
		result.bytes.Add(received)
	})
}

func measureConnectedUDP(options options, deadline time.Time, result *counters) error {
	return runWorkers(options.concurrency, func() {
		address, err := net.ResolveUDPAddr("udp", options.target)
		if err != nil {
			result.errors.Add(1)
			return
		}
		connection, err := net.DialUDP("udp", nil, address)
		if err != nil {
			result.errors.Add(1)
			return
		}
		defer connection.Close()
		payload := make([]byte, options.udpPayloadSize)
		response := make([]byte, options.udpPayloadSize)
		for time.Now().Before(deadline) {
			_ = connection.SetDeadline(deadline)
			if _, err = connection.Write(payload); err != nil {
				if time.Now().Before(deadline) {
					result.errors.Add(1)
				}
				break
			}
			n, readErr := connection.Read(response)
			if readErr != nil || n != len(payload) {
				if time.Now().Before(deadline) {
					result.errors.Add(1)
				}
				break
			}
			result.operations.Add(1)
			result.bytes.Add(uint64(n))
		}
	})
}

func measureUnconnectedUDP(options options, deadline time.Time, result *counters) error {
	return runWorkers(options.concurrency, func() {
		address, err := net.ResolveUDPAddr("udp", options.target)
		if err != nil {
			result.errors.Add(1)
			return
		}
		connection, err := net.ListenUDP("udp", nil)
		if err != nil {
			result.errors.Add(1)
			return
		}
		defer connection.Close()
		payload := make([]byte, options.udpPayloadSize)
		response := make([]byte, options.udpPayloadSize)
		for time.Now().Before(deadline) {
			_ = connection.SetDeadline(deadline)
			if _, err = connection.WriteToUDP(payload, address); err != nil {
				if time.Now().Before(deadline) {
					result.errors.Add(1)
				}
				break
			}
			n, _, readErr := connection.ReadFromUDP(response)
			if readErr != nil || n != len(payload) {
				if time.Now().Before(deadline) {
					result.errors.Add(1)
				}
				break
			}
			result.operations.Add(1)
			result.bytes.Add(uint64(n))
		}
	})
}

func measureUDPChurn(options options, deadline time.Time, result *counters) error {
	return runWorkers(options.concurrency, func() {
		address, err := net.ResolveUDPAddr("udp", options.target)
		if err != nil {
			result.errors.Add(1)
			return
		}
		payload := make([]byte, options.udpPayloadSize)
		response := make([]byte, options.udpPayloadSize)
		for time.Now().Before(deadline) {
			connection, dialErr := net.DialUDP("udp", nil, address)
			if dialErr != nil {
				if time.Now().Before(deadline) {
					result.errors.Add(1)
				}
				continue
			}
			_ = connection.SetDeadline(deadline)
			_, writeErr := connection.Write(payload)
			n, readErr := connection.Read(response)
			_ = connection.Close()
			if writeErr != nil || readErr != nil || n != len(payload) {
				if time.Now().Before(deadline) {
					result.errors.Add(1)
				}
				continue
			}
			result.operations.Add(1)
			result.bytes.Add(uint64(n))
		}
	})
}

func runWorkers(count int, worker func()) error {
	var waitGroup sync.WaitGroup
	waitGroup.Add(count)
	for range count {
		go func() {
			defer waitGroup.Done()
			worker()
		}()
	}
	waitGroup.Wait()
	return nil
}

func remainingTimeout(deadline time.Time, maximum time.Duration) time.Duration {
	remaining := time.Until(deadline)
	if remaining < maximum {
		return remaining
	}
	return maximum
}

func isTimeout(err error) bool {
	var networkError net.Error
	return errors.As(err, &networkError) && networkError.Timeout()
}
