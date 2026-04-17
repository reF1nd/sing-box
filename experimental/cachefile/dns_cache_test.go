package cachefile

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/sagernet/bbolt"

	"github.com/stretchr/testify/require"
)

func newDNSCacheTestCache(t *testing.T) *CacheFile {
	t.Helper()

	database, err := bbolt.Open(filepath.Join(t.TempDir(), "cache.db"), 0o600, nil)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, database.Close())
	})
	return &CacheFile{
		DB:           database,
		saveDNSCache: make(map[saveCacheKey]saveDNSCacheEntry),
	}
}

func TestDeleteDNSCacheDeletesOnlyMatchingValue(t *testing.T) {
	t.Parallel()

	cache := newDNSCacheTestCache(t)
	const (
		transportName = "local"
		questionName  = "example.com."
		questionType  = uint16(1)
	)
	expireAt := time.Now().Add(time.Hour)
	corruptMessage := []byte("corrupt")
	require.NoError(t, cache.SaveDNSCache(transportName, questionName, questionType, corruptMessage, expireAt))

	cache.DeleteDNSCache(transportName, questionName, questionType, corruptMessage)

	_, _, loaded := cache.LoadDNSCache(transportName, questionName, questionType)
	require.False(t, loaded)
}

func TestDeleteDNSCacheSeparatesClientSubnetValue(t *testing.T) {
	t.Parallel()

	cache := newDNSCacheTestCache(t)
	const (
		plainTransportName = "local"
		ecsTransportName   = "local\x00192.0.2.0/24"
		questionName       = "example.com."
		questionType       = uint16(1)
	)
	expireAt := time.Now().Add(time.Hour)
	plainMessage := []byte("plain")
	ecsMessage := []byte("ecs")
	require.NoError(t, cache.SaveDNSCache(plainTransportName, questionName, questionType, plainMessage, expireAt))
	require.NoError(t, cache.SaveDNSCache(ecsTransportName, questionName, questionType, ecsMessage, expireAt))

	cache.DeleteDNSCache(ecsTransportName, questionName, questionType, ecsMessage)

	_, _, loaded := cache.LoadDNSCache(ecsTransportName, questionName, questionType)
	require.False(t, loaded)
	actualPlainMessage, _, loaded := cache.LoadDNSCache(plainTransportName, questionName, questionType)
	require.True(t, loaded)
	require.Equal(t, plainMessage, actualPlainMessage)
}

func TestDeleteDNSCachePreservesNewerValue(t *testing.T) {
	t.Parallel()

	cache := newDNSCacheTestCache(t)
	const (
		transportName = "local"
		questionName  = "example.com."
		questionType  = uint16(1)
	)
	expireAt := time.Now().Add(time.Hour)
	corruptMessage := []byte("corrupt")
	freshMessage := []byte("fresh")
	require.NoError(t, cache.SaveDNSCache(transportName, questionName, questionType, corruptMessage, expireAt))
	loadedMessage, _, loaded := cache.LoadDNSCache(transportName, questionName, questionType)
	require.True(t, loaded)
	require.Equal(t, corruptMessage, loadedMessage)
	require.NoError(t, cache.SaveDNSCache(transportName, questionName, questionType, freshMessage, expireAt))

	cache.DeleteDNSCache(transportName, questionName, questionType, loadedMessage)

	actualMessage, _, loaded := cache.LoadDNSCache(transportName, questionName, questionType)
	require.True(t, loaded)
	require.Equal(t, freshMessage, actualMessage)
}

func TestDeleteDNSCachePreservesPendingValue(t *testing.T) {
	t.Parallel()

	cache := newDNSCacheTestCache(t)
	const (
		transportName = "local\x00192.0.2.0/24"
		questionName  = "example.com."
		questionType  = uint16(1)
	)
	expireAt := time.Now().Add(time.Hour)
	corruptMessage := []byte("corrupt")
	freshMessage := []byte("fresh")
	require.NoError(t, cache.SaveDNSCache(transportName, questionName, questionType, corruptMessage, expireAt))
	saveKey := saveCacheKey{transportName, questionName, questionType}
	require.True(t, cache.queueDNSCacheSave(saveKey, freshMessage, expireAt))

	cache.DeleteDNSCache(transportName, questionName, questionType, corruptMessage)

	actualMessage, _, loaded := cache.LoadDNSCache(transportName, questionName, questionType)
	require.True(t, loaded)
	require.Equal(t, freshMessage, actualMessage)
}
