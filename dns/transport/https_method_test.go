package transport

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/sagernet/sing-box/dns"
	M "github.com/sagernet/sing/common/metadata"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestHTTPSRequestMethods(t *testing.T) {
	for _, method := range []string{"", http.MethodPost, http.MethodGet} {
		t.Run("method="+method, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				expected := method
				if expected == "" {
					expected = http.MethodPost
				}
				if r.Method != expected || r.URL.Query().Get("token") != "keep" {
					t.Errorf("unexpected request: %s %s", r.Method, r.URL)
				}
				var data []byte
				var err error
				if expected == http.MethodGet {
					data, err = base64.RawURLEncoding.DecodeString(r.URL.Query().Get("dns"))
					if r.ContentLength != 0 {
						t.Error("GET must not have a body")
					}
				} else {
					data, err = io.ReadAll(r.Body)
					if r.Header.Get("Content-Type") != MimeType {
						t.Error("missing DNS content type")
					}
				}
				if err != nil {
					t.Error(err)
					w.WriteHeader(400)
					return
				}
				var request mDNS.Msg
				if err = request.Unpack(data); err != nil {
					t.Error(err)
					w.WriteHeader(400)
					return
				}
				response := new(mDNS.Msg).SetReply(&request)
				data, err = response.Pack()
				if err != nil {
					t.Error(err)
					w.WriteHeader(500)
					return
				}
				w.Header().Set("Content-Type", MimeType)
				_, _ = w.Write(data)
			}))
			defer server.Close()
			destination, err := url.Parse(server.URL + "/dns-query?token=keep")
			require.NoError(t, err)
			transport := NewHTTPSRaw(dns.TransportAdapter{}, nil, nil, destination, method, http.Header{}, M.Socksaddr{}, nil)
			transport.transport.httpTransport = http.DefaultTransport.(*http.Transport).Clone()
			defer transport.Close()
			message := new(mDNS.Msg).SetQuestion("example.com.", mDNS.TypeA)
			response, err := transport.exchange(context.Background(), message)
			require.NoError(t, err)
			require.Equal(t, message.Question, response.Question)
			require.Equal(t, "token=keep", destination.RawQuery)
		})
	}
}
