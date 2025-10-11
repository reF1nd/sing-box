package anytls

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"

	"github.com/stretchr/testify/require"
)

func TestOutboundTCPFastOpen(t *testing.T) {
	outbound, err := NewOutbound(context.Background(), nil, logger.NOP(), "test", option.AnyTLSOutboundOptions{
		DialerOptions:               option.DialerOptions{AbstractDialerOptions: option.AbstractDialerOptions{TCPFastOpen: true}},
		ServerOptions:               option.ServerOptions{Server: "127.0.0.1", ServerPort: 443},
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: &option.OutboundTLSOptions{Enabled: true}},
		Password:                    "password",
	})
	require.NoError(t, err)
	scope := adapter.NewScope(t.Context(), log.NewNOPFactory().Logger())
	t.Cleanup(func() { _ = scope.Close() })
	require.NoError(t, outbound.(*Outbound).Start(adapter.StartStateInitialize, scope))
	require.NoError(t, scope.Close())
}
