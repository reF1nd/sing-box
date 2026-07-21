package anytls

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestInterfaceUpdated(t *testing.T) {
	require.NotPanics(t, (&Outbound{}).InterfaceUpdated)
}
