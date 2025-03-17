package trafficcontrol

import (
	"testing"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/stretchr/testify/require"
)

func TestTrackerMetadataConnectionDomain(t *testing.T) {
	testCases := []struct {
		name        string
		destination M.Socksaddr
		domain      string
		sniffHost   string
		expected    string
	}{
		{
			name:      "sniff host",
			sniffHost: "sniff.example.com",
			expected:  "sniff.example.com",
		},
		{
			name:      "sniff host before reverse mapped domain",
			domain:    "mapped.example.com",
			sniffHost: "sniff.example.com",
			expected:  "sniff.example.com",
		},
		{
			name:     "reverse mapped domain fallback",
			domain:   "mapped.example.com",
			expected: "mapped.example.com",
		},
		{
			name:        "destination fqdn before cached domains",
			destination: M.ParseSocksaddr("destination.example.com:443"),
			domain:      "mapped.example.com",
			sniffHost:   "sniff.example.com",
			expected:    "destination.example.com",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			metadata := TrackerMetadata{Metadata: adapter.InboundContext{
				Destination: testCase.destination,
				Domain:      testCase.domain,
				SniffHost:   testCase.sniffHost,
			}}
			require.Equal(t, testCase.expected, metadata.ConnectionDomain())
		})
	}
}
