package sniff_test

import (
	"context"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/sniff"
	C "github.com/sagernet/sing-box/constant"

	"github.com/stretchr/testify/require"
)

func TestSniffHTTP1(t *testing.T) {
	t.Parallel()
	pkt := "GET / HTTP/1.1\r\nHost: www.google.com\r\nAccept: */*\r\n\r\n"
	var metadata adapter.InboundContext
	err := sniff.HTTPHost(context.Background(), &metadata, strings.NewReader(pkt))
	require.NoError(t, err)
	require.Equal(t, metadata.SniffHost, "www.google.com")
}

func TestSniffHTTP1WithPort(t *testing.T) {
	t.Parallel()
	pkt := "GET / HTTP/1.1\r\nHost: www.gov.cn:8080\r\nAccept: */*\r\n\r\n"
	var metadata adapter.InboundContext
	err := sniff.HTTPHost(context.Background(), &metadata, strings.NewReader(pkt))
	require.NoError(t, err)
	require.Equal(t, metadata.SniffHost, "www.gov.cn")
}

func TestSniffHTTPHostPreservesDomainCache(t *testing.T) {
	for _, testCase := range []struct {
		host      string
		sniffHost string
	}{
		{"example.com", "example.com"},
		{"example.com:8080", "example.com"},
		{"192.0.2.1", ""},
		{"192.0.2.1:8080", ""},
		{"[2001:db8::1]", ""},
		{"[2001:db8::1]:8080", ""},
	} {
		t.Run(testCase.host, func(t *testing.T) {
			metadata := adapter.InboundContext{Domain: "cached.example"}
			packet := "GET / HTTP/1.1\r\nHost: " + testCase.host + "\r\n\r\n"
			err := sniff.HTTPHost(t.Context(), &metadata, strings.NewReader(packet))
			require.NoError(t, err)
			require.Equal(t, C.ProtocolHTTP, metadata.Protocol)
			require.Equal(t, testCase.sniffHost, metadata.SniffHost)
			require.Equal(t, "cached.example", metadata.Domain)
		})
	}
}
