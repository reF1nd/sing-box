package route

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"

	snell "github.com/sagernet/sing-snell"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
)

func TestConnectionCopySnellErrorLevel(t *testing.T) {
	t.Parallel()
	decode := func(code byte, message string) error {
		return snell.ReadServerError(buf.As(append([]byte{code, byte(len(message))}, message...)))
	}
	remoteEOF := decode(101, "Remote EOF")
	malformed := snell.ReadServerError(buf.As(append([]byte{101, 10}, []byte("Remote EOF!")...)))
	for _, testCase := range []struct {
		name  string
		err   error
		level string
	}{
		{"remote-eof", remoteEOF, "debug"},
		{"wrapped", fmt.Errorf("read reply: %w", remoteEOF), "debug"},
		{"cause", E.Cause(remoteEOF, "read reply"), "debug"},
		{"extended", E.Extend(remoteEOF, "read reply"), "debug"},
		{"other-message", decode(101, "Other failure"), "error"},
		{"other-code", decode(1, "Remote EOF"), "error"},
		{"same-text", errors.New(remoteEOF.Error()), "error"},
		{"malformed", malformed, "error"},
		{"joined", errors.Join(remoteEOF, io.ErrUnexpectedEOF), "error"},
		{"normal-eof", io.EOF, "debug"},
		{"closed", net.ErrClosed, "trace"},
	} {
		for _, direction := range []string{"upload", "download"} {
			t.Run(testCase.name+"/"+direction, func(t *testing.T) {
				t.Parallel()
				log := &snellErrorTestLogger{}
				manager := NewConnectionManager(log)
				source := &snellErrorTestConn{readErr: testCase.err}
				destination := &snellErrorTestConn{}
				var done atomic.Bool
				done.Store(true)
				called := false
				var closeErr error
				manager.connectionCopy(context.Background(), source, destination, direction == "download", &done, func(err error) {
					called = true
					closeErr = err
				})
				if log.count != 1 || log.level != testCase.level {
					t.Fatalf("level = %q, want %q; message = %q", log.level, testCase.level, log.message)
				}
				if !called || !source.closed || !destination.closed {
					t.Fatal("connection cleanup or callback was skipped")
				}
				wantErr := testCase.err
				wantMessage := "connection " + direction + " closed: " + testCase.err.Error()
				if testCase.err == io.EOF {
					wantErr = nil
					wantMessage = "connection " + direction + " finished"
				} else if testCase.level == "trace" {
					wantMessage = "connection " + direction + " closed"
				}
				if closeErr != wantErr {
					t.Fatalf("callback error changed: got %v, want %v", closeErr, wantErr)
				}
				if log.message != wantMessage {
					t.Fatalf("message = %q, want %q", log.message, wantMessage)
				}
			})
		}
	}
}

type snellErrorTestConn struct {
	net.Conn
	readErr error
	closed  bool
}

func (c *snellErrorTestConn) Read([]byte) (int, error)    { return 0, c.readErr }
func (c *snellErrorTestConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *snellErrorTestConn) Close() error                { c.closed = true; return nil }

type snellErrorTestLogger struct {
	logger.ContextLogger
	count   int
	level   string
	message string
}

func (l *snellErrorTestLogger) record(level string, args []any) {
	l.count++
	l.level = level
	var message strings.Builder
	for _, arg := range args {
		fmt.Fprint(&message, arg)
	}
	l.message = message.String()
}

func (l *snellErrorTestLogger) DebugContext(_ context.Context, args ...any) { l.record("debug", args) }

func (l *snellErrorTestLogger) TraceContext(_ context.Context, args ...any) { l.record("trace", args) }

func (l *snellErrorTestLogger) ErrorContext(_ context.Context, args ...any) { l.record("error", args) }
