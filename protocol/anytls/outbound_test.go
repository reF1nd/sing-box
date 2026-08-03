package anytls

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestInterfaceUpdated(t *testing.T) {
	require.NotPanics(t, (&Outbound{}).InterfaceUpdated)
}

func TestMultiplexEnabled(t *testing.T) {
	require.True(t, (&Outbound{}).MultiplexEnabled())
	require.False(t, (&Outbound{disableReuse: true}).MultiplexEnabled())
}
