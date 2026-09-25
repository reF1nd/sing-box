package v2rayhttp

import (
	"errors"
	"io"
	"net"
	"net/http"
	"testing"

	"golang.org/x/net/http2"
)

type serverTestWriter struct {
	n   int
	err error
}

func (w serverTestWriter) Write([]byte) (int, error) {
	return w.n, w.err
}

type serverTestResponseWriter struct {
	flushed  bool
	flushErr error
}

func (w *serverTestResponseWriter) Header() http.Header         { return http.Header{} }
func (w *serverTestResponseWriter) Write(p []byte) (int, error) { return len(p), nil }
func (w *serverTestResponseWriter) WriteHeader(int)             {}
func (w *serverTestResponseWriter) FlushError() error {
	w.flushed = true
	return w.flushErr
}

func TestServerHTTPConnWrite(t *testing.T) {
	protocolError := http2.StreamError{StreamID: 169, Code: http2.ErrCodeProtocol, Cause: errors.New("peer reset")}
	internalError := http2.StreamError{StreamID: 169, Code: http2.ErrCodeInternal}
	cancelError := http2.StreamError{StreamID: 169, Code: http2.ErrCodeCancel}
	flushError := errors.New("flush failed")
	for _, test := range []struct {
		name     string
		n        int
		err      error
		flushErr error
		closed   bool
		want     error
	}{
		{name: "success", n: 7},
		{name: "flush_error", n: 7, flushErr: flushError, want: flushError},
		{name: "closed", closed: true, want: net.ErrClosed},
		{name: "protocol_error", err: protocolError, want: protocolError},
		{name: "partial_internal_error", n: 3, err: internalError, want: internalError},
		{name: "cancel", err: cancelError, want: net.ErrClosed},
		{name: "unexpected_eof", err: io.ErrUnexpectedEOF, want: io.EOF},
		{name: "partial_short_write", n: 3, err: io.ErrShortWrite, want: io.ErrShortWrite},
	} {
		t.Run(test.name, func(t *testing.T) {
			rw := &serverTestResponseWriter{flushErr: test.flushErr}
			conn := &ServerHTTPConn{
				HTTP2Conn:  NewHTTPConn(nil, serverTestWriter{n: test.n, err: test.err}),
				Controller: http.NewResponseController(rw),
			}
			if test.closed {
				_ = conn.Close()
			}
			n, err := conn.Write([]byte("payload"))
			if n != test.n {
				t.Fatalf("byte count = %d, want %d", n, test.n)
			}
			if _, bare := err.(http2.StreamError); bare {
				t.Fatal("server write leaked a bare HTTP/2 stream error")
			}
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
			if want, ok := test.want.(http2.StreamError); ok {
				var original http2.StreamError
				if !errors.As(err, &original) || original != want {
					t.Fatalf("lost original stream error: %v", err)
				}
			} else if err != test.want {
				t.Fatalf("error = %v, want canonical error %v", err, test.want)
			}
			wantFlushed := !test.closed && test.err == nil
			if rw.flushed != wantFlushed {
				t.Fatalf("flushed = %v, want %v", rw.flushed, wantFlushed)
			}
		})
	}
}
