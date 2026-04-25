package clashapi

import (
	"context"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/interrupt"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/service"
	"github.com/stretchr/testify/require"
	"net/http"
	"testing"
	"time"
)

type resourceDownloadTransport struct {
	adapter.HTTPTransport
	roundTrip func(*http.Request) (*http.Response, error)
}

func (t *resourceDownloadTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return t.roundTrip(r)
}
func (*resourceDownloadTransport) CloseIdleConnections() {}

type resourceDownloadManager struct {
	adapter.HTTPClientManager
	transport adapter.HTTPTransport
}

func (m *resourceDownloadManager) DefaultTransport() adapter.HTTPTransport { return m.transport }

func TestExternalUIResourceDownloadContext(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	deadline, _ := ctx.Deadline()
	called := false
	transport := &resourceDownloadTransport{roundTrip: func(r *http.Request) (*http.Response, error) {
		called = true
		require.True(t, interrupt.IsResourceDownloadFromContext(r.Context()))
		actual, ok := r.Context().Deadline()
		require.True(t, ok)
		require.Equal(t, deadline, actual)
		cancel()
		require.ErrorIs(t, r.Context().Err(), context.Canceled)
		return nil, r.Context().Err()
	}}
	ctx = service.ContextWith[adapter.HTTPClientManager](ctx, &resourceDownloadManager{transport: transport})
	server := &Server{ctx: ctx, logger: log.NewNOPFactory().NewLogger("test"), externalUIDownloadURL: "https://example.com/dashboard.zip"}
	require.ErrorIs(t, server.downloadExternalUI(), context.Canceled)
	require.True(t, called)
}
