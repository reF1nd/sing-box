package daemon

import (
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/trafficcontrol"
	"github.com/stretchr/testify/require"
)

func TestBuildConnectionProtoUsesSniffHost(t *testing.T) {
	metadata := &trafficcontrol.TrackerMetadata{
		Metadata: adapter.InboundContext{
			SniffHost: "sniff.example.com",
		},
		Upload:   new(atomic.Int64),
		Download: new(atomic.Int64),
	}

	require.Equal(t, "sniff.example.com", buildConnectionProto(metadata).Domain)
}
