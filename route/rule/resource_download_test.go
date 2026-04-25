package rule

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/interrupt"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"

	"github.com/stretchr/testify/require"
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
	p, err := NewRemoteRuleSet(ctx, log.NewNOPFactory().NewLogger("test"), "test", option.RuleSet{Type: "remote", Format: "source", RemoteOptions: option.RemoteRuleSet{URL: "https://example.com/rules.json"}})
	require.NoError(t, err)
	p.httpClient = client
	require.ErrorIs(t, p.fetch(ctx, true), context.Canceled)
	require.True(t, called)
}
