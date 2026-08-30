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
		{"unsupported errno", unix.EOPNOTSUPP, KernelProbeFail},
		{"android unsupported errno", linuxErrnoNotSupported, KernelProbeFail},
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
	report.Add(KernelProbeFail, "local", KernelProbePerformance, "three", "")
	report.Add(KernelProbeUnknown, "shared", KernelProbeRequired, "four", "")
	if failures := report.RequiredFailures(); failures != 1 {
		t.Fatalf("unexpected required failure count: %d", failures)
	}
	counts := report.Counts()
	if counts[KernelProbePass] != 1 || counts[KernelProbeFail] != 2 || counts[KernelProbeUnknown] != 1 {
		t.Fatalf("unexpected counts: %v", counts)
	}
	if unknowns := report.RequiredUnknowns(); unknowns != 1 {
		t.Fatalf("unexpected required unknown count: %d", unknowns)
	}
	if issues := report.RequiredIssues(); issues != 2 {
		t.Fatalf("unexpected required issue count: %d", issues)
	}
	if err := report.RequiredError(); err == nil || !strings.Contains(err.Error(), "two") {
		t.Fatalf("unexpected required error: %v", err)
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
		KernelRelease: "5.7.0-test",
		Architecture:  "arm64",
		Mode:          KernelProbeModeLocal,
		IPv6:          true,
	}
	report.Add(KernelProbePass, "common", KernelProbeRequired, "hash map", "available")
	report.Add(KernelProbeUnknown, "local", KernelProbeRequired, "TC hook", "permission required")
	var output bytes.Buffer
	if err := WriteKernelProbeReport(&output, report); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		"kernel: 5.7.0-test",
		"ipv6: true",
		"cilium/ebpf direct bpf(2) probes",
		"PASS",
		"UNKNOWN",
		"Summary: PASS=1 WARN=0 FAIL=0 UNKNOWN=1 REQUIRED_FAILURES=0 REQUIRED_UNKNOWNS=1",
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
		Mode:          KernelProbeModeShared,
		Network:       []string{"tcp", "udp"},
		ActivePrograms: []KernelProbeProgram{{
			ID:       42,
			Name:     "sb_share_in",
			Type:     CiliumEBPF.SchedCLS,
			MapCount: 3,
		}},
	}
	report.Add(KernelProbePass, "common", KernelProbeRequired, "hash map", "available")
	report.Add(KernelProbeFail, "shared", KernelProbeRequired, "sched_cls", "unavailable")
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
