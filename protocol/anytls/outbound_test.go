package anytls

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/logger"

	"github.com/anytls/sing-anytls/util"
	"github.com/stretchr/testify/require"
)

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
		require.Empty(t, outbound.clientOptions.ClientMetadata)
		require.NoError(t, outbound.Start(adapter.StartStateInitialize))
		require.NoError(t, outbound.Close())
	}
}

func TestInterfaceUpdated(t *testing.T) {
	require.NotPanics(t, func() { (&Outbound{}).InterfaceUpdated(context.Background()) })
}

func TestClientMetadataOrDefault(t *testing.T) {
	require.Equal(t, util.Version+" sing-box/"+C.Version, clientMetadataOrDefault(nil))
	emptyMetadata := ""
	require.Empty(t, clientMetadataOrDefault(&emptyMetadata))
	customMetadata := "custom"
	require.Equal(t, customMetadata, clientMetadataOrDefault(&customMetadata))
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

func TestMultiplexEnabled(t *testing.T) {
	require.True(t, (&Outbound{}).MultiplexEnabled())
	require.False(t, (&Outbound{disableReuse: true}).MultiplexEnabled())
}
