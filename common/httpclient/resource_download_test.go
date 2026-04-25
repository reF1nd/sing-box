package httpclient

import (
	"context"
	"fmt"
	boxTLS "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/sagernet/sing-box/common/interrupt"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/stretchr/testify/require"
)

type downloadTestDialer struct {
	N.Dialer
	access   sync.Mutex
	policies []bool
}

func (d *downloadTestDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	d.access.Lock()
	d.policies = append(d.policies, interrupt.IsResourceDownloadFromContext(ctx))
	d.access.Unlock()
	return (&net.Dialer{}).DialContext(ctx, network, destination.String())
}

func TestResourceDownloadConnectionPoolIsolation(t *testing.T) {
	for _, version := range []int{1, 2} {
		for _, firstDownload := range []bool{false, true} {
			name := "ordinary-first"
			if firstDownload {
				name = "download-first"
			}
			t.Run(fmt.Sprintf("http%d/%s", version, name), func(t *testing.T) {
				server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") }))
				server.EnableHTTP2 = version == 2
				var tlsConfig boxTLS.Config
				if version == 2 {
					server.StartTLS()
					var err error
					tlsConfig, err = boxTLS.NewSTDClient(context.Background(), logger.NOP(), "", option.OutboundTLSOptions{Enabled: true, Insecure: true})
					require.NoError(t, err)
				} else {
					server.Start()
				}
				defer server.Close()
				dialer := new(downloadTestDialer)
				transport := &ManagedTransport{cheapRebuild: true, factory: func(download bool) (innerTransport, error) {
					return newTransport(resourceDownloadDialer(dialer, download), tlsConfig, option.HTTPClientOptions{Version: version, DisableVersionFallback: true})
				}}
				defer transport.close()
				shared := new(sharedState)
				clients := []*http.Client{{Transport: newSharedRef(transport, shared)}, {Transport: newSharedRef(transport, shared)}}
				request := func(download bool) {
					ctx := context.Background()
					if download {
						ctx = interrupt.ContextWithIsResourceDownload(ctx)
					}
					req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
					require.NoError(t, err)
					index := 0
					if download {
						index = 1
					}
					resp, err := clients[index].Do(req)
					require.NoError(t, err)
					require.Equal(t, version, resp.ProtoMajor)
					_, err = io.ReadAll(resp.Body)
					require.NoError(t, err)
					require.NoError(t, resp.Body.Close())
				}
				for range 2 {
					request(firstDownload)
					request(!firstDownload)
				}
				dialer.access.Lock()
				require.Equal(t, []bool{firstDownload, !firstDownload}, dialer.policies)
				dialer.access.Unlock()
				transport.Reset()
				request(firstDownload)
				request(!firstDownload)
				transport.CloseIdleConnections()
				request(firstDownload)
				request(!firstDownload)
				dialer.access.Lock()
				require.Equal(t, []bool{firstDownload, !firstDownload, firstDownload, !firstDownload, firstDownload, !firstDownload}, dialer.policies)
				dialer.access.Unlock()
			})
		}
	}

}

func TestResourceDownloadResetPreservesActiveBody(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "first")
		w.(http.Flusher).Flush()
		select {
		case <-release:
			_, _ = io.WriteString(w, "second")
		case <-r.Context().Done():
		}
	}))
	defer server.Close()
	dialer := new(downloadTestDialer)
	transport := &ManagedTransport{cheapRebuild: true, factory: func(download bool) (innerTransport, error) {
		return newHTTP1Transport(resourceDownloadDialer(dialer, download), nil), nil
	}}
	defer transport.close()
	ctx, cancel := context.WithCancel(interrupt.ContextWithIsResourceDownload(context.Background()))
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	resp, err := transport.RoundTrip(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	first := make([]byte, 5)
	_, err = io.ReadFull(resp.Body, first)
	require.NoError(t, err)
	transport.Reset()
	transport.CloseIdleConnections()
	close(release)
	rest, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, "firstsecond", string(first)+string(rest))
}
