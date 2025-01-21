package urltest

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

type unifiedTestDialer struct{ N.Dialer }

func (unifiedTestDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, destination.String())
}

func TestUnifiedDelayIsolatedContexts(t *testing.T) {
	var single, unified atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/single" {
			single.Add(1)
		} else {
			unified.Add(1)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	base := context.Background()
	enabled := ContextWithUnifiedDelay(base, true)
	disabled := ContextWithUnifiedDelay(base, false)
	require.False(t, UnifiedDelayFromContext(base))
	require.True(t, UnifiedDelayFromContext(enabled))
	require.False(t, UnifiedDelayFromContext(ContextWithUnifiedDelay(enabled, false)))
	var wg sync.WaitGroup
	for range 5 {
		wg.Go(func() {
			_, err := URLTest(enabled, server.URL+"/unified", unifiedTestDialer{})
			require.NoError(t, err)
		})
		wg.Go(func() {
			_, err := URLTest(disabled, server.URL+"/single", unifiedTestDialer{})
			require.NoError(t, err)
		})
	}
	wg.Wait()
	require.EqualValues(t, 10, unified.Load())
	require.EqualValues(t, 5, single.Load())
	ctx, cancel := context.WithCancel(ContextWithUnifiedDelay(base, true))
	cancel()
	_, err := URLTest(ctx, server.URL+"/unified", unifiedTestDialer{})
	require.ErrorIs(t, err, context.Canceled)
}
