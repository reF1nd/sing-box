package quic

import (
	"context"
	"net/http"
	"testing"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"

	"github.com/stretchr/testify/require"
)

func TestNewHTTP3PathQueryPreserved(t *testing.T) {
	var opts option.RemoteHTTPSDNSServerOptions
	opts.Server = "127.0.0.1"
	opts.ServerPort = 443
	opts.Path = "/dns-query?token=keep"
	opts.Method = http.MethodGet
	opts.TLS = &option.OutboundTLSOptions{
		Enabled:    true,
		ServerName: "dns.example.com",
	}
	created, err := NewHTTP3(context.Background(), log.NewNOPFactory().NewLogger("dns"), "doh3", opts)
	require.NoError(t, err)
	h3Transport := created.(*HTTP3Transport)
	require.Equal(t, "/dns-query", h3Transport.destination.Path)
	require.Equal(t, "token=keep", h3Transport.destination.RawQuery)
	require.Equal(t, "https://dns.example.com/dns-query?token=keep", h3Transport.destination.String())

	badOpts := opts
	badOpts.Path = "/dns-query?token=%ZZ"
	_, err = NewHTTP3(context.Background(), log.NewNOPFactory().NewLogger("dns"), "doh3-bad", badOpts)
	require.Error(t, err)

	postOpts := opts
	postOpts.Method = http.MethodPost
	postOpts.Path = "/dns-query?token=a;b"
	postCreated, err := NewHTTP3(context.Background(), log.NewNOPFactory().NewLogger("dns"), "doh3-post", postOpts)
	require.NoError(t, err)
	require.Equal(t, "token=a;b", postCreated.(*HTTP3Transport).destination.RawQuery)
}
