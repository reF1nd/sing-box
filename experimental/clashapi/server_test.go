package clashapi

import (
	"crypto/sha256"
	"testing"

	"github.com/sagernet/sing-box/adapter"

	"github.com/stretchr/testify/require"
)

func TestExternalUICacheMatchesURL(t *testing.T) {
	currentURLHash := sha256.Sum256([]byte("https://example.com/current.zip"))
	otherURLHash := sha256.Sum256([]byte("https://example.com/other.zip"))

	require.True(t, externalUICacheMatchesURL(&adapter.SavedBinary{}, currentURLHash))
	require.True(t, externalUICacheMatchesURL(&adapter.SavedBinary{URLHash: currentURLHash[:]}, currentURLHash))
	require.False(t, externalUICacheMatchesURL(&adapter.SavedBinary{URLHash: otherURLHash[:]}, currentURLHash))
}
