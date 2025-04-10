package cachefile

import (
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"

	"github.com/stretchr/testify/require"
)

func TestExternalUICacheRoundTrip(t *testing.T) {
	t.Parallel()

	cache := newDNSCacheTestCache(t)
	expected := &adapter.SavedBinary{
		Content:     []byte{},
		LastUpdated: time.Unix(1_750_000_000, 0),
		LastEtag:    `"external-ui-etag"`,
		URLHash:     []byte("external-ui-url-hash"),
	}
	require.NoError(t, cache.SaveExternalUI("ExternalUI", expected))
	require.Equal(t, expected, cache.LoadExternalUI("ExternalUI"))
}
