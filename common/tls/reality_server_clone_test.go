//go:build with_utls

package tls

import (
	"testing"
	"time"

	utls "github.com/metacubex/utls"
	"github.com/stretchr/testify/require"
)

func TestRealityServerClonePreservesSNIPolicy(t *testing.T) {
	config := &RealityServerConfig{
		config:           &utls.RealityConfig{ServerNames: map[string]bool{"one.example": true}},
		handshakeTimeout: time.Second,
		rejectUnknownSNI: true,
	}
	clone := config.Clone().(*RealityServerConfig)
	require.True(t, clone.rejectUnknownSNI)
	require.Equal(t, config.config.ServerNames, clone.config.ServerNames)
	require.Equal(t, config.handshakeTimeout, clone.handshakeTimeout)
}
