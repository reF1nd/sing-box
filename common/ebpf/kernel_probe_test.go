//go:build with_ebpf && (linux || android)

package ebpf

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	CiliumEBPF "github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

func TestClassifyKernelProbeError(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		status KernelProbeStatus
	}{
		{"supported", nil, KernelProbePass},
		{"unsupported", CiliumEBPF.ErrNotSupported, KernelProbeFail},
		{"wrapped unsupported", errors.Join(errors.New("probe"), CiliumEBPF.ErrNotSupported), KernelProbeFail},
		{"permission denied", unix.EPERM, KernelProbeUnknown},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if status := classifyKernelProbeError(test.err); status != test.status {
				t.Fatalf("unexpected status: got %s, want %s", status, test.status)
			}
		})
	}
}

func TestKernelProbeReportCounts(t *testing.T) {
	report := &KernelProbeReport{}
	report.Add(KernelProbePass, "common", KernelProbeRequired, "one", "")
	report.Add(KernelProbeFail, "local", KernelProbeRequired, "two", "")
	report.Add(KernelProbeFail, "local", KernelProbeFallback, "three", "")
	report.Add(KernelProbeUnknown, "shared-network", KernelProbeRequired, "four", "")
	if failures := report.RequiredFailures(); failures != 1 {
		t.Fatalf("unexpected required failure count: %d", failures)
	}
	counts := report.Counts()
	if counts[KernelProbePass] != 1 || counts[KernelProbeFail] != 2 || counts[KernelProbeUnknown] != 1 {
		t.Fatalf("unexpected counts: %v", counts)
	}
}

func TestMemlockProbeResult(t *testing.T) {
	status, detail := memlockProbeResult(
		unix.Rlimit{Cur: 8 << 20, Max: 8 << 20},
		nil,
		unix.EPERM,
	)
	if status != KernelProbeWarn || !strings.Contains(detail, "soft=8388608, hard=8388608") ||
		!strings.Contains(detail, "operation not permitted") || !strings.Contains(detail, "may be inconclusive") {
		t.Fatalf("unexpected limited memlock result: status=%s detail=%q", status, detail)
	}
	status, detail = memlockProbeResult(
		unix.Rlimit{Cur: unix.RLIM_INFINITY, Max: unix.RLIM_INFINITY},
		nil,
		nil,
	)
	if status != KernelProbePass || !strings.Contains(detail, "after automatic adjustment") {
		t.Fatalf("unexpected unlimited memlock result: status=%s detail=%q", status, detail)
	}
	status, detail = memlockProbeResult(unix.Rlimit{}, unix.EIO, unix.EPERM)
	if status != KernelProbeUnknown || !strings.Contains(detail, "automatic adjustment also failed") {
		t.Fatalf("unexpected unreadable memlock result: status=%s detail=%q", status, detail)
	}
}

func TestWriteKernelProbeReport(t *testing.T) {
	report := &KernelProbeReport{
		Platform:      "Linux",
		KernelRelease: "4.19.0-test",
		Architecture:  "arm64",
		Mode:          KernelProbeModeLocal,
	}
	report.Add(KernelProbePass, "common", KernelProbeRequired, "hash map", "available")
	report.Add(KernelProbeUnknown, "local", KernelProbeRequired, "cgroup", "permission required")
	var output bytes.Buffer
	if err := WriteKernelProbeReport(&output, report); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		"kernel: 4.19.0-test",
		"cilium/ebpf direct bpf(2) probes",
		"PASS",
		"UNKNOWN",
		"Summary: PASS=1 WARN=0 FAIL=0 UNKNOWN=1",
	} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("report is missing %q:\n%s", expected, output.String())
		}
	}
}

func TestWriteKernelProbeReportJSON(t *testing.T) {
	report := &KernelProbeReport{
		Platform:      "Android",
		KernelRelease: "6.6.30-test",
		Architecture:  "arm64",
		Mode:          KernelProbeModeSharedNetwork,
		Network:       []string{"tcp", "udp"},
		ActivePrograms: []KernelProbeProgram{{
			ID:       42,
			Name:     "sb_share_in",
			Type:     CiliumEBPF.SchedCLS,
			MapCount: 3,
		}},
	}
	report.Add(KernelProbePass, "common", KernelProbeRequired, "hash map", "available")
	report.Add(KernelProbeFail, "shared-network", KernelProbeRequired, "sched_cls", "unavailable")
	var output bytes.Buffer
	if err := WriteKernelProbeReportJSON(&output, report); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), `"Status"`) || !strings.Contains(output.String(), `"status"`) {
		t.Fatalf("unexpected finding field names: %s", output.String())
	}
	var decoded struct {
		KernelRelease  string `json:"kernel_release"`
		Result         string `json:"result"`
		ActivePrograms []struct {
			ID   uint32 `json:"id"`
			Type string `json:"type"`
		} `json:"active_programs"`
		Summary struct {
			RequiredFailures int `json:"required_failures"`
		} `json:"summary"`
	}
	if err := json.Unmarshal(output.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.KernelRelease != report.KernelRelease || decoded.Result != "unsupported" ||
		decoded.Summary.RequiredFailures != 1 || len(decoded.ActivePrograms) != 1 ||
		decoded.ActivePrograms[0].ID != 42 || decoded.ActivePrograms[0].Type != CiliumEBPF.SchedCLS.String() {
		t.Fatalf("unexpected JSON report: %+v", decoded)
	}
}

func TestPathWithin(t *testing.T) {
	for _, test := range []struct {
		path string
		root string
		want bool
	}{
		{"/sys/fs/cgroup", "/sys/fs/cgroup", true},
		{"/sys/fs/cgroup/sing-box", "/sys/fs/cgroup", true},
		{"/sys/fs/cgroup2", "/sys/fs/cgroup", false},
		{"/sys/fs", "/sys/fs/cgroup", false},
	} {
		if got := pathWithin(test.path, test.root); got != test.want {
			t.Fatalf("pathWithin(%q, %q)=%v, want %v", test.path, test.root, got, test.want)
		}
	}
}

func TestKernelVersionCode(t *testing.T) {
	version := kernelVersionCode(5, 2, 300)
	if formatted := formatKernelVersionCode(version); formatted != "5.2.255" {
		t.Fatalf("unexpected formatted version: %s", formatted)
	}
}

func TestParseKernelProbeNetwork(t *testing.T) {
	tcp, udp, network, err := parseKernelProbeNetwork([]string{"udp", "tcp", "udp"})
	if err != nil {
		t.Fatal(err)
	}
	if !tcp || !udp || strings.Join(network, ",") != "tcp,udp" {
		t.Fatalf("unexpected network result: tcp=%v udp=%v network=%v", tcp, udp, network)
	}
	if _, _, _, err = parseKernelProbeNetwork([]string{"icmp"}); err == nil {
		t.Fatal("expected invalid network error")
	}
}
