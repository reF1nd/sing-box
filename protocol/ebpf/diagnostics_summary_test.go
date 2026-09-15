//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"strings"
	"testing"

	commonEBPF "github.com/CHIZI-0618/sing-ebpf"
)

type captureLogger struct {
	debugMessages []string
	infoMessages  []string
}

func (l *captureLogger) Trace(args ...any) {}
func (l *captureLogger) Debug(args ...any) {
	var builder strings.Builder
	for _, arg := range args {
		if text, ok := arg.(string); ok {
			builder.WriteString(text)
		}
	}
	l.debugMessages = append(l.debugMessages, builder.String())
}
func (l *captureLogger) Info(args ...any)  { l.infoMessages = append(l.infoMessages, "called") }
func (l *captureLogger) Warn(args ...any)  {}
func (l *captureLogger) Error(args ...any) {}
func (l *captureLogger) Fatal(args ...any) {}
func (l *captureLogger) Panic(args ...any) {}

func (l *captureLogger) TraceContext(context.Context, ...any)        {}
func (l *captureLogger) DebugContext(_ context.Context, args ...any) { l.Debug(args...) }
func (l *captureLogger) InfoContext(ctx context.Context, args ...any) {
	l.Info(args...)
}
func (l *captureLogger) WarnContext(context.Context, ...any)  {}
func (l *captureLogger) ErrorContext(context.Context, ...any) {}
func (l *captureLogger) FatalContext(context.Context, ...any) {}
func (l *captureLogger) PanicContext(context.Context, ...any) {}

// TestLogStartupSummaryNamesEachRequiredFact checks enabled paths, mounts,
// waiting interfaces, and FakeIP coverage in the single Debug line.
func TestLogStartupSummaryNamesEachRequiredFact(t *testing.T) {
	logger := &captureLogger{}
	inbound := &Inbound{
		localEnabled:    true,
		localDataPlane:  localDataPlaneTC,
		fakeIPICMPReply: true,
		logger:          logger,
	}
	inbound.logStartupSummary()

	if len(logger.debugMessages) != 1 || len(logger.infoMessages) != 0 {
		t.Fatalf("log calls: Debug=%d Info=%d, want Debug=1 Info=0", len(logger.debugMessages), len(logger.infoMessages))
	}
	message := logger.debugMessages[0]
	for _, want := range []string{"local=tc", "waiting_for_interface=[local]", "fakeip_icmp=[enabled, not yet covering any attachment]"} {
		if !strings.Contains(message, want) {
			t.Fatalf("summary %q missing %q", message, want)
		}
	}
}

// TestLogStartupSummaryReportsAnActualAttachmentAndItsFakeIPICMPCoverage
// covers the other half: a real attachment gets named by interface and
// mechanism, and when fakeip_icmp actually covers it, that attachment name
// appears rather than the "not yet covering" fallback.
func TestLogStartupSummaryReportsAnActualAttachmentAndItsFakeIPICMPCoverage(t *testing.T) {
	logger := &captureLogger{}
	inbound := &Inbound{
		localEnabled:    true,
		localDataPlane:  localDataPlaneTC,
		fakeIPICMPReply: true,
		logger:          logger,
	}
	inbound.tcDataPlane = &testTCRuntime{
		attachments: []commonEBPF.AttachmentInfo{{
			InterfaceName: "eth0",
			Role:          "local",
			Mechanism:     "tcx",
			ICMPEchoReply: true,
		}},
	}
	inbound.logStartupSummary()

	if len(logger.debugMessages) != 1 || len(logger.infoMessages) != 0 {
		t.Fatalf("log calls: Debug=%d Info=%d, want Debug=1 Info=0", len(logger.debugMessages), len(logger.infoMessages))
	}
	message := logger.debugMessages[0]
	for _, want := range []string{"mounts=[eth0(local,tcx)]", "waiting_for_interface=[none]", "fakeip_icmp=[eth0(local)]"} {
		if !strings.Contains(message, want) {
			t.Fatalf("summary %q missing %q", message, want)
		}
	}
}
