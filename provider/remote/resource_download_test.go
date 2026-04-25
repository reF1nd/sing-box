package remote

import (
	"context"
	"github.com/sagernet/sing-box/common/interrupt"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/stretchr/testify/require"
	"net/http"
	"testing"
	"time"
)

type resourceDownloadRoundTripper func(*http.Request) (*http.Response, error)

func (f resourceDownloadRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestResourceDownloadRequestContext(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	deadline, _ := ctx.Deadline()
	called := false
	client := &http.Client{Transport: resourceDownloadRoundTripper(func(r *http.Request) (*http.Response, error) {
		called = true
		require.True(t, interrupt.IsResourceDownloadFromContext(r.Context()))
		actual, ok := r.Context().Deadline()
		require.True(t, ok)
		require.Equal(t, deadline, actual)
		cancel()
		require.ErrorIs(t, r.Context().Err(), context.Canceled)
		return nil, r.Context().Err()
	})}
	p, err := NewProviderRemote(ctx, nil, log.NewNOPFactory(), "test", option.ProviderRemoteOptions{URL: "https://example.com/provider"})
	require.NoError(t, err)
	p.(*ProviderRemote).httpClient = client
	require.ErrorIs(t, p.(*ProviderRemote).fetch(ctx, true), context.Canceled)
	require.True(t, called)
}
