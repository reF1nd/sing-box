package option

import (
	"context"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

type stubDNSTransportOptionsRegistry struct{}

func (stubDNSTransportOptionsRegistry) OptionTypes() []string {
	return []string{C.DNSTypeUDP, C.DNSTypeFakeIP}
}

func (stubDNSTransportOptionsRegistry) CreateOptions(transportType string) (any, bool) {
	switch transportType {
	case C.DNSTypeUDP:
		return new(RemoteDNSServerOptions), true
	case C.DNSTypeFakeIP:
		return new(FakeIPDNSServerOptions), true
	default:
		return nil, false
	}
}

func TestDNSOptionsRejectsLegacyFakeIPOptions(t *testing.T) {
	t.Parallel()

	ctx := service.ContextWith[DNSTransportOptionsRegistry](context.Background(), stubDNSTransportOptionsRegistry{})
	var options DNSOptions
	err := json.UnmarshalContext(ctx, []byte(`{
		"fakeip": {
			"enabled": true,
			"inet4_range": "198.18.0.0/15"
		}
	}`), &options)
	require.EqualError(t, err, legacyDNSFakeIPRemovedMessage)
}

func TestDNSServerOptionsRejectsLegacyFormats(t *testing.T) {
	t.Parallel()

	ctx := service.ContextWith[DNSTransportOptionsRegistry](context.Background(), stubDNSTransportOptionsRegistry{})
	testCases := []string{
		`{"address":"1.1.1.1"}`,
		`{"type":"legacy","address":"1.1.1.1"}`,
	}
	for _, content := range testCases {
		var options DNSServerOptions
		err := json.UnmarshalContext(ctx, []byte(content), &options)
		require.EqualError(t, err, legacyDNSServerRemovedMessage)
	}
}

func TestHTTPSMethodSerialization(t *testing.T) {
	ctx := context.Background()
	for _, method := range []string{"", "POST", "GET"} {
		options := RemoteHTTPSDNSServerOptions{Method: method}
		content, err := json.MarshalContext(ctx, &options)
		require.NoError(t, err)
		require.Equal(t, method, options.Method, "serialization must not change runtime configuration")
		var decoded RemoteHTTPSDNSServerOptions
		require.NoError(t, json.UnmarshalContext(ctx, content, &decoded))
		expected := method
		if expected == "" {
			expected = "POST"
		}
		require.Equal(t, expected, decoded.Method)
	}
	var invalid RemoteHTTPSDNSServerOptions
	require.Error(t, json.UnmarshalContext(ctx, []byte(`{"method":"PUT"}`), &invalid))
}
