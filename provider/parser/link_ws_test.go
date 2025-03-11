package parser

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"testing"

	"github.com/sagernet/sing-box/option"
	"github.com/stretchr/testify/require"
)

func TestParseLinkWebsocketEarlyData(t *testing.T) {
	tests := []struct {
		path      string
		wantPath  string
		earlyData uint32
		enabled   bool
	}{
		{"/ws", "/ws", 0, false},
		{"/ws?foo=bar", "/ws?foo=bar", 0, false},
		{"/ws?ed=2048", "/ws", 2048, true},
		{"/ws?ed=2048&foo=bar", "/ws?foo=bar", 2048, true},
		{"/ws?foo=bar&ed=2048", "/ws?foo=bar", 2048, true},
		{"/ws?foo=bar&ed=2048&baz=1", "/ws?foo=bar&baz=1", 2048, true},
		{"/ws?z=%2f+%20&ed=2048&a=1&a=2", "/ws?z=%2f+%20&a=1&a=2", 2048, true},
		{"/ws?%65d=%32%30%34%38&foo=bar", "/ws?foo=bar", 2048, true},
		{"/ws?ed=2048&ed=1024", "/ws", 2048, true},
		{"/ws?ed=0", "/ws", 0, true},
		{"/ws?ed=4294967295", "/ws", 4294967295, true},
		{"/ws?ed=4294967296&foo=bar", "/ws?ed=4294967296&foo=bar", 0, false},
		{"/ws?ed=&foo=bar", "/ws?ed=&foo=bar", 0, false},
		{"/ws?ed=invalid&foo=bar", "/ws?ed=invalid&foo=bar", 0, false},
		{"/ws?ed=-1", "/ws?ed=-1", 0, false},
		{"/ws?ed=%2B1", "/ws?ed=%2B1", 0, false},
		{"/ws?ed=%zz", "/ws?ed=%zz", 0, false},
		{"/ws?foo=%zz&ed=2048", "/ws?foo=%zz", 2048, true},
		{"/ws?foo=bar&ed=2048#fragment", "/ws?foo=bar#fragment", 2048, true},
		{"/ws#fragment?ed=2048", "/ws#fragment?ed=2048", 0, false},
	}
	for _, protocol := range []string{"vless", "vmess", "trojan"} {
		for _, tt := range tests {
			t.Run(protocol+"/"+tt.path, func(t *testing.T) {
				link := protocol + "://11111111-1111-1111-1111-111111111111@example.com:443?type=ws&path=" + url.QueryEscape(tt.path)
				if protocol == "vmess" {
					payload := fmt.Sprintf(`{"add":"example.com","port":"443","id":"11111111-1111-1111-1111-111111111111","net":"ws","path":%q}`, tt.path)
					link = "vmess://" + base64.RawURLEncoding.EncodeToString([]byte(payload))
				}
				outbound, err := ParseSubscriptionLink(link)
				require.NoError(t, err)
				var transport *option.V2RayTransportOptions
				switch options := outbound.Options.(type) {
				case *option.VLESSOutboundOptions:
					transport = options.Transport
				case *option.VMessOutboundOptions:
					transport = options.Transport
				case *option.TrojanOutboundOptions:
					transport = options.Transport
				}
				require.NotNil(t, transport)
				require.Equal(t, tt.wantPath, transport.WebsocketOptions.Path)
				require.Equal(t, tt.earlyData, transport.WebsocketOptions.MaxEarlyData)
				header := ""
				if tt.enabled {
					header = "Sec-WebSocket-Protocol"
				}
				require.Equal(t, header, transport.WebsocketOptions.EarlyDataHeaderName)
			})
		}
	}
}
