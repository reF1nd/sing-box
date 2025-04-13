package clashapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/service"
	"github.com/stretchr/testify/require"
)

type restartTestCloser func() error

func (f restartTestCloser) Close() error { return f() }

func TestRestartFlushesThenClosesBeforeExec(t *testing.T) {
	recorder := httptest.NewRecorder()
	closed := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	executed := make(chan string, 1)
	var calls atomic.Int32
	ctx := service.ContextWith[adapter.BoxCloser](context.Background(), restartTestCloser(func() error {
		calls.Add(1)
		if !recorder.Flushed {
			t.Error("response was not flushed before shutdown")
		}
		close(closed)
		<-release
		return nil
	}))
	handler := restartHandler(ctx, log.NewNOPFactory().Logger(), func() (string, error) { return "/test/sing-box", nil }, func(path string) error { executed <- path; return nil })
	handler(recorder, httptest.NewRequest(http.MethodPost, "/restart", nil))
	require.Equal(t, http.StatusOK, recorder.Code)
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("shutdown did not begin")
	}
	select {
	case <-executed:
		t.Fatal("executed before shutdown completed")
	default:
	}
	duplicate := httptest.NewRecorder()
	handler(duplicate, httptest.NewRequest(http.MethodPost, "/restart", nil))
	require.Equal(t, http.StatusConflict, duplicate.Code)
	require.EqualValues(t, 1, calls.Load())
	unblock()
	select {
	case path := <-executed:
		require.Equal(t, "/test/sing-box", path)
	case <-time.After(time.Second):
		t.Fatal("restart did not follow shutdown")
	}

}

func TestRestartPreflightFailureDoesNotClose(t *testing.T) {
	for _, missing := range []bool{false, true} {
		ctx := context.Background()
		if !missing {
			ctx = service.ContextWith[adapter.BoxCloser](ctx, restartTestCloser(func() error { t.Error("closed on preflight failure"); return nil }))
		}
		handler := restartHandler(ctx, log.NewNOPFactory().Logger(), func() (string, error) { return "", errors.New("no executable") }, func(string) error { t.Error("restarted on preflight failure"); return nil })
		recorder := httptest.NewRecorder()
		handler(recorder, httptest.NewRequest(http.MethodPost, "/restart", nil))
		if missing {
			require.Equal(t, http.StatusServiceUnavailable, recorder.Code)
		} else {
			require.Equal(t, http.StatusInternalServerError, recorder.Code)
		}
	}
}
