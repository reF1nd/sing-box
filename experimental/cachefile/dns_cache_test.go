package cachefile

import (
	"encoding/binary"
	"path/filepath"
	"testing"
	"time"

	"github.com/sagernet/bbolt"
	"github.com/sagernet/sing/common/logger"

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
		DB:      database,
		logger:  logger.NOP(),
		pending: newPendingWrites(),
	}
}

func TestDNSCacheFlushFailurePreservesPendingValue(t *testing.T) {
	t.Parallel()

	databasePath := filepath.Join(t.TempDir(), "cache.db")
	database, err := bbolt.Open(databasePath, 0o600, nil)
	require.NoError(t, err)
	require.NoError(t, database.Close())
	database, err = bbolt.Open(databasePath, 0o600, &bbolt.Options{ReadOnly: true})
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, database.Close())
	})
	cache := &CacheFile{
		DB:      database,
		logger:  logger.NOP(),
		pending: newPendingWrites(),
	}
	const (
		transportName = "local"
		questionName  = "example.com."
		questionType  = uint16(1)
	)
	rawMessage := []byte("pending")
	expireAt := time.Now().Add(time.Hour)
	cache.queueDNSCache(transportName, questionName, questionType, rawMessage, expireAt)

	cache.Flush()

	actualMessage, actualExpireAt, loaded := cache.LoadDNSCache(transportName, questionName, questionType)
	require.True(t, loaded)
	require.Equal(t, rawMessage, actualMessage)
	require.Equal(t, expireAt.Unix(), actualExpireAt.Unix())
}

func TestDNSCacheFlushFailurePreservesNewerPendingValue(t *testing.T) {
	t.Parallel()

	cache := &CacheFile{pending: newPendingWrites()}
	const (
		transportName = "local"
		questionName  = "example.com."
		questionType  = uint16(1)
	)
	expireAt := time.Now().Add(time.Hour)
	oldMessage := []byte("old")
	newMessage := []byte("new")
	failedWrites := newPendingWrites()
	failedValue := make([]byte, 8+len(oldMessage))
	binary.BigEndian.PutUint64(failedValue[:8], uint64(expireAt.Unix()))
	copy(failedValue[8:], oldMessage)
	key := saveCacheKey{transportName, questionName, questionType}
	failedWrites.dnsCache[key] = saveDNSCacheEntry{value: failedValue}
	failedWrites.count = 1
	failedWrites.size = len(questionName) + len(failedValue)
	cache.queueDNSCache(transportName, questionName, questionType, newMessage, expireAt)

	cache.pendingAccess.Lock()
	cache.restorePendingLocked(failedWrites)
	cache.pendingAccess.Unlock()

	actualMessage, _, loaded := cache.LoadDNSCache(transportName, questionName, questionType)
	require.True(t, loaded)
	require.Equal(t, newMessage, actualMessage)
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

func TestDeleteDNSCacheDeletesMatchingPendingValue(t *testing.T) {
	t.Parallel()

	cache := newDNSCacheTestCache(t)
	const (
		transportName = "local"
		questionName  = "example.com."
		questionType  = uint16(1)
	)
	expireAt := time.Now().Add(time.Hour)
	corruptMessage := []byte("corrupt")
	cache.queueDNSCache(transportName, questionName, questionType, corruptMessage, expireAt)

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
	cache.queueDNSCache(transportName, questionName, questionType, freshMessage, expireAt)

	cache.DeleteDNSCache(transportName, questionName, questionType, corruptMessage)

	actualMessage, _, loaded := cache.LoadDNSCache(transportName, questionName, questionType)
	require.True(t, loaded)
	require.Equal(t, freshMessage, actualMessage)
}
