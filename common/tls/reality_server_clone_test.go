//go:build with_utls

package tls

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"

	utls "github.com/metacubex/utls"
	"github.com/stretchr/testify/require"
)

func TestRealityServerClonePreservesSNIPolicy(t *testing.T) {
	config := &RealityServerConfig{
		config:           &utls.RealityConfig{ServerNames: map[string]bool{"one.example": true}},
		handshakeTimeout: time.Second,
		rejectUnknownSNI: true,
		serverNames:      map[string]bool{"one.example": true},
	}
	clone := config.Clone().(*RealityServerConfig)
	require.True(t, clone.rejectUnknownSNI)
	require.Equal(t, config.config.ServerNames, clone.config.ServerNames)
	require.Equal(t, config.serverNames, clone.serverNames)
	require.Equal(t, config.handshakeTimeout, clone.handshakeTimeout)
}

func TestRealityServerUnnamedPreservesEmptyUnderlyingServerNameKey(t *testing.T) {
	privateKey := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	server, err := NewRealityServer(context.Background(), logger.NOP(), option.InboundTLSOptions{
		Enabled:          true,
		RejectUnknownSNI: true,
		Reality: &option.InboundRealityOptions{
			Enabled:    true,
			PrivateKey: privateKey,
			Handshake: option.InboundRealityHandshakeOptions{
				ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: 443},
			},
		},
	})
	require.NoError(t, err)
	realityServer := server.(*RealityServerConfig)
	require.Empty(t, realityServer.serverNames)
	require.Equal(t, map[string]bool{"": true}, realityServer.config.ServerNames)

	named, err := NewRealityServer(context.Background(), logger.NOP(), option.InboundTLSOptions{
		Enabled:          true,
		ServerNames:      []string{"one.example", "two.example"},
		RejectUnknownSNI: true,
		Reality: &option.InboundRealityOptions{
			Enabled:    true,
			PrivateKey: privateKey,
			Handshake: option.InboundRealityHandshakeOptions{
				ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: 443},
			},
		},
	})
	require.NoError(t, err)
	namedServer := named.(*RealityServerConfig)
	require.Equal(t, map[string]bool{"one.example": true, "two.example": true}, namedServer.serverNames)
	require.Equal(t, map[string]bool{"one.example": true, "two.example": true}, namedServer.config.ServerNames)
}
