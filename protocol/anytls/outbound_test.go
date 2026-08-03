package anytls

import (
	"context"
	"testing"

	"github.com/anytls/sing-anytls/util"
	"github.com/stretchr/testify/require"
)

func TestInterfaceUpdated(t *testing.T) {
	require.NotPanics(t, func() { (&Outbound{}).InterfaceUpdated(context.Background()) })
}

func TestClientMetadataOrDefault(t *testing.T) {
	require.Equal(t, util.Version, clientMetadataOrDefault(nil))
	emptyMetadata := ""
	require.Empty(t, clientMetadataOrDefault(&emptyMetadata))
	customMetadata := "custom"
	require.Equal(t, customMetadata, clientMetadataOrDefault(&customMetadata))
}

func TestMultiplexEnabled(t *testing.T) {
	require.True(t, (&Outbound{}).MultiplexEnabled())
	require.False(t, (&Outbound{disableReuse: true}).MultiplexEnabled())
}
