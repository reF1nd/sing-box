package anytls

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestInterfaceUpdated(t *testing.T) {
	require.NotPanics(t, func() { (&Outbound{}).InterfaceUpdated(context.Background()) })
}
