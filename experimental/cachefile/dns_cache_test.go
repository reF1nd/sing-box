package cachefile

import (
	"encoding/binary"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/sagernet/bbolt"
	"github.com/sagernet/sing-box/adapter"
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

func TestRDRCFlushFailurePreservesExpiresAt(t *testing.T) {
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
	key := saveCacheKey{"local", "blocked.example.", 1}
	oldExpire := time.Now().Add(time.Hour).Truncate(time.Second)
	cache.pending.rdrc[key] = oldExpire
	cache.pending.count++

	cache.Flush()

	require.Equal(t, oldExpire, cache.pending.rdrc[key])

	// Newer pending RDRC expiry must take precedence over restored older entry.
	newerExpire := oldExpire.Add(2 * time.Hour)
	writing := newPendingWrites()
	writing.rdrc[key] = oldExpire
	cache.pending.rdrc[key] = newerExpire
	cache.restorePendingLocked(writing)
	require.Equal(t, newerExpire, cache.pending.rdrc[key])
}

func TestFakeIPReserveFailureDoesNotOrphanMetadata(t *testing.T) {
	t.Parallel()

	databasePath := filepath.Join(t.TempDir(), "cache.db")
	prefix := netip.MustParsePrefix("198.18.0.0/24")
	initialMeta := &adapter.FakeIPMetadata{
		Inet4Range:   prefix,
		Inet4Current: netip.MustParseAddr("198.18.0.1"),
	}
	advancedMeta := &adapter.FakeIPMetadata{
		Inet4Range:   prefix,
		Inet4Current: netip.MustParseAddr("198.18.0.5"),
	}
	staleAddr := netip.MustParseAddr("198.18.0.2")

	// Seed initial metadata and an existing FakeIP mapping inside (198.18.0.1, 198.18.0.5].
	db, err := bbolt.Open(databasePath, 0o600, nil)
	require.NoError(t, err)
	seed := &CacheFile{DB: db, logger: logger.NOP(), pending: newPendingWrites()}
	require.NoError(t, seed.FakeIPSaveMetadata(initialMeta))
	require.NoError(t, seed.FakeIPStore(staleAddr, "stale.example."))
	require.NoError(t, db.Close())

	// Open read-only so FakeIPReserve fails while an ordinary DNS write is pending.
	roDB, err := bbolt.Open(databasePath, 0o600, &bbolt.Options{ReadOnly: true})
	require.NoError(t, err)
	cache := &CacheFile{DB: roDB, logger: logger.NOP(), pending: newPendingWrites()}
	cache.queueDNSCache("local", "keep.example.", 1, []byte("dns-msg"), time.Now().Add(time.Hour))

	err = cache.FakeIPReserve(advancedMeta, initialMeta.Inet4Current, advancedMeta.Inet4Current)
	require.Error(t, err)
	require.Nil(t, cache.pending.fakeIPMetadata, "failed FakeIPReserve must not leave orphaned metadata in pending")
	_, _, loaded := cache.LoadDNSCache("local", "keep.example.", 1)
	require.True(t, loaded, "ordinary pending DNS write must be restored after failed reserve")
	require.NoError(t, roDB.Close())

	// Reopen writable and run an ordinary Flush(): DNS entry persists, metadata stays initial, stale mapping intact.
	rwDB, err := bbolt.Open(databasePath, 0o600, nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, rwDB.Close()) })
	cache.DB = rwDB
	cache.Flush()

	require.Equal(t, initialMeta.Inet4Current, cache.FakeIPMetadata().Inet4Current)
	domain, found := cache.FakeIPLoad(staleAddr)
	require.True(t, found)
	require.Equal(t, "stale.example.", domain)

	// Retry FakeIPReserve atomically: advances metadata AND deletes stale mapping in one transaction.
	require.NoError(t, cache.FakeIPReserve(advancedMeta, initialMeta.Inet4Current, advancedMeta.Inet4Current))
	require.Equal(t, advancedMeta.Inet4Current, cache.FakeIPMetadata().Inet4Current)
	_, found = cache.FakeIPLoad(staleAddr)
	require.False(t, found)
}

func TestFakeIPResetFailurePreservesPendingRecords(t *testing.T) {
	t.Parallel()

	databasePath := filepath.Join(t.TempDir(), "cache.db")
	persistedAddr := netip.MustParseAddr("198.18.0.2")
	pendingAddr := netip.MustParseAddr("198.18.0.3")

	db, err := bbolt.Open(databasePath, 0o600, nil)
	require.NoError(t, err)
	seed := &CacheFile{DB: db, logger: logger.NOP(), pending: newPendingWrites()}
	require.NoError(t, seed.FakeIPStore(persistedAddr, "persisted.example."))
	seed.Flush()
	require.NoError(t, db.Close())

	roDB, err := bbolt.Open(databasePath, 0o600, &bbolt.Options{ReadOnly: true})
	require.NoError(t, err)
	cache := &CacheFile{DB: roDB, logger: logger.NOP(), pending: newPendingWrites()}
	cache.FakeIPStoreAsync(pendingAddr, "pending.example.", logger.NOP())

	err = cache.FakeIPReset()
	require.Error(t, err)

	domain, found := cache.FakeIPLoad(pendingAddr)
	require.True(t, found)
	require.Equal(t, "pending.example.", domain)
	addr, found := cache.FakeIPLoadDomain("pending.example.", false)
	require.True(t, found)
	require.Equal(t, pendingAddr, addr)

	domain, found = cache.FakeIPLoad(persistedAddr)
	require.True(t, found)
	require.Equal(t, "persisted.example.", domain)
	require.NoError(t, roDB.Close())

	rwDB, err := bbolt.Open(databasePath, 0o600, nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, rwDB.Close()) })
	cache.DB = rwDB
	require.NoError(t, cache.FakeIPReset())

	_, found = cache.FakeIPLoad(pendingAddr)
	require.False(t, found)
	_, found = cache.FakeIPLoadDomain("pending.example.", false)
	require.False(t, found)
	_, found = cache.FakeIPLoad(persistedAddr)
	require.False(t, found)
}
