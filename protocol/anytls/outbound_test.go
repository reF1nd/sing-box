package anytls

import (
	"context"
	"testing"

	anytls "github.com/sagernet/sing-anytls"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/logger"

	"github.com/stretchr/testify/require"
)

func TestClientMetadataOrDefault(t *testing.T) {
	require.Equal(t, anytls.DefaultClientMetadata+" sing-box/"+C.Version, clientMetadataOrDefault(nil))
	require.Empty(t, clientMetadataOrDefault(common.Ptr("")))
	require.Equal(t, "custom", clientMetadataOrDefault(common.Ptr("custom")))
	for _, data := range []string{`{}`, `{"client_metadata":""}`, `{"client_metadata":"custom"}`} {
		var options option.AnyTLSOutboundOptions
		require.NoError(t, json.Unmarshal([]byte(data), &options))
		encoded, err := json.Marshal(options)
		require.NoError(t, err)
		var roundTrip option.AnyTLSOutboundOptions
		require.NoError(t, json.Unmarshal(encoded, &roundTrip))
		require.Equal(t, options.ClientMetadata, roundTrip.ClientMetadata)
	}
}

func TestOutboundOptions(t *testing.T) {
	for _, disableReuse := range []bool{false, true} {
		created, err := NewOutbound(context.Background(), nil, logger.NOP(), "test", option.AnyTLSOutboundOptions{
			DialerOptions:               option.DialerOptions{AbstractDialerOptions: option.AbstractDialerOptions{TCPFastOpen: true}},
			ServerOptions:               option.ServerOptions{Server: "127.0.0.1", ServerPort: 443},
			OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: &option.OutboundTLSOptions{Enabled: true}},
			Password:                    "password", DisableReuse: disableReuse, ClientMetadata: common.Ptr(""),
		})
		require.NoError(t, err)
		outbound := created.(*Outbound)
		require.Equal(t, disableReuse, outbound.clientOptions.DisableReuse)
		require.Equal(t, !disableReuse, outbound.MultiplexEnabled())
		require.NotNil(t, outbound.clientOptions.ClientMetadata)
		require.Empty(t, *outbound.clientOptions.ClientMetadata)
		require.NoError(t, outbound.Start(adapter.StartStateInitialize))
		require.NoError(t, outbound.Close())
	}
}

func TestIdleMethodsBeforeStart(t *testing.T) {
	outbound := new(Outbound)
	require.NotPanics(t, func() {
		outbound.InterfaceUpdated(context.Background())
		outbound.SetKeepIdleConnections(false)
		outbound.CloseIdleConnections()
	})
	require.NoError(t, outbound.Close())
}

func TestALPNFallbackRequiresTLS(t *testing.T) {
	_, err := NewInbound(context.Background(), nil, logger.NOP(), "test", option.AnyTLSInboundOptions{
		FallbackForALPN: map[string]*option.ServerOptions{"h2": {Server: "127.0.0.1", ServerPort: 80}},
	})
	require.ErrorContains(t, err, "fallback for ALPN is not supported without TLS")
}
