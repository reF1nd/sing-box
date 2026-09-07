package v2rayhttp

import (
	"errors"
	"fmt"
	"io"
	"net"
	"testing"

	"golang.org/x/net/http2"
)

type errorReaderWriter struct {
	err error
}

func (rw errorReaderWriter) Read([]byte) (int, error) {
	return 0, rw.err
}

func (rw errorReaderWriter) Write([]byte) (int, error) {
	return 0, rw.err
}

type testFlusher struct {
	flushed bool
}

func (f *testFlusher) Flush() {
	f.flushed = true
}

func TestHTTP2ConnStreamError(t *testing.T) {
	for _, code := range []http2.ErrCode{http2.ErrCodeProtocol, http2.ErrCodeInternal} {
		t.Run(code.String(), func(t *testing.T) {
			original := http2.StreamError{StreamID: 169, Code: code, Cause: errors.New("peer reset")}
			rw := errorReaderWriter{original}
			conn := NewHTTPConn(rw, rw)
			late := NewLateHTTPConn(rw)
			late.Setup(nil, original)
			flusher := new(testFlusher)
			server := &ServerHTTPConn{HTTP2Conn: NewHTTPConn(rw, rw), Flusher: flusher}
			for name, operation := range map[string]func([]byte) (int, error){
				"read": conn.Read, "setup": late.Read, "write": conn.Write, "server_write": server.Write,
			} {
				t.Run(name, func(t *testing.T) {
					n, err := operation(make([]byte, 1))
					if n != 0 {
						t.Fatalf("unexpected byte count: %d", n)
					}
					if _, naked := err.(http2.StreamError); naked {
						t.Fatal("transport leaked a bare HTTP/2 stream error")
					}
					var streamError http2.StreamError
					if !errors.Is(err, original) || !errors.As(err, &streamError) || streamError != original {
						t.Fatalf("lost original stream error: %v", err)
					}
				})
			}
			if flusher.flushed {
				t.Fatal("flushed after a failed write")
			}
		})
	}
}

func TestHTTP2ConnClosedErrors(t *testing.T) {
	for _, original := range []error{io.EOF, io.ErrUnexpectedEOF, http2.StreamError{StreamID: 1, Code: http2.ErrCodeCancel}} {
		t.Run(original.Error(), func(t *testing.T) {
			want := error(io.EOF)
			if _, ok := original.(http2.StreamError); ok {
				want = net.ErrClosed
			}
			rw := errorReaderWriter{original}
			conn := NewHTTPConn(rw, rw)
			late := NewLateHTTPConn(rw)
			late.Setup(nil, original)
			for _, read := range []func([]byte) (int, error){conn.Read, late.Read} {
				_, err := read(make([]byte, 1))
				if err != want {
					t.Fatalf("expected canonical error %v, got %v", want, err)
				}
			}
		})
	}
}

type partialReaderWriter struct {
	err error
}

func (rw partialReaderWriter) Read(p []byte) (int, error) {
	p[0] = 'x'
	return 1, rw.err
}

func (rw partialReaderWriter) Write([]byte) (int, error) {
	return 1, rw.err
}

func TestHTTP2ConnPartialIO(t *testing.T) {
	original := http2.StreamError{StreamID: 1, Code: http2.ErrCodeProtocol}
	wrapped := fmt.Errorf("transport: %w", original)
	for _, expected := range []error{nil, original, wrapped, io.ErrShortWrite, io.EOF} {
		t.Run(fmt.Sprint(expected), func(t *testing.T) {
			rw := partialReaderWriter{expected}
			conn := NewHTTPConn(rw, rw)
			flusher := new(testFlusher)
			server := &ServerHTTPConn{HTTP2Conn: conn, Flusher: flusher}
			for _, operation := range []func([]byte) (int, error){conn.Read, conn.Write, server.Write} {
				n, err := operation(make([]byte, 2))
				if n != 1 || !errors.Is(err, expected) {
					t.Fatalf("lost partial I/O result: n=%d err=%v", n, err)
				}
				if expected != original && err != expected {
					t.Fatalf("unnecessarily wrapped error: %v", err)
				}
			}
			if flusher.flushed != (expected == nil) {
				t.Fatal("server must flush only successful writes")
			}
		})
	}
}
