package cachefile

import (
	"context"
	"net/netip"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/bbolt"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"

	"github.com/stretchr/testify/require"
)

type retryTestLogger struct {
	logger.Logger
	failures atomic.Int32
}

func (l *retryTestLogger) Warn(...any) { l.failures.Add(1) }

func newRetryTestCache(t *testing.T) (*CacheFile, *retryTestLogger, func()) {
	t.Helper()
	log := &retryTestLogger{Logger: logger.NOP()}
	cache := New(context.Background(), log, option.CacheFileOptions{})
	cache.rdrcTimeout = time.Hour
	path := filepath.Join(t.TempDir(), "cache.db")
	db, err := bbolt.Open(path, 0o600, nil)
	require.NoError(t, err)
	require.NoError(t, db.Close())
	cache.DB = db
	t.Cleanup(func() { cache.stopCacheWriter(); _ = cache.database().Close() })
	recoverDB := func() {
		cache.cacheWriteAccess.Lock()
		defer cache.cacheWriteAccess.Unlock()
		database, openErr := bbolt.Open(path, 0o600, nil)
		require.NoError(t, openErr)
		cache.dbAccess.Lock()
		cache.DB = database
		cache.dbAccess.Unlock()
	}
	return cache, log, recoverDB
}

func TestCacheWriterRetriesAllCachesAfterRecovery(t *testing.T) {
	cache, log, recoverDB := newRetryTestCache(t)
	address := netip.MustParseAddr("198.18.0.1")
	metadata := &adapter.FakeIPMetadata{Inet4Range: netip.MustParsePrefix("198.18.0.0/15"), Inet4Current: address}
	expireAt := time.Now().Add(time.Hour)
	cache.SaveDNSCacheAsync("dns", "example.com.", 1, []byte("answer"), expireAt, log)
	cache.SaveRDRCAsync("dns", "blocked.example.", 1, log)
	cache.FakeIPStoreAsync(address, "fake.example", log)
	cache.FakeIPSaveMetadataAsync(metadata)
	cache.saveMetadataAccess.Lock()
	cache.saveMetadataDue = time.Now()
	cache.saveMetadataAccess.Unlock()
	cache.wakeCacheWriter()
	require.Eventually(t, func() bool { return log.failures.Load() >= 4 }, 3*time.Second, time.Millisecond)
	require.True(t, cache.LoadRDRC("dns", "blocked.example.", 1))
	domain, loaded := cache.FakeIPLoad(address)
	require.True(t, loaded)
	require.Equal(t, "fake.example", domain)
	recoverDB()
	// No new writes or wakeup: the scheduled retry must persist all four caches.
	require.Eventually(t, func() bool {
		cache.saveDNSCacheAccess.RLock()
		dnsEmpty := len(cache.saveDNSCache) == 0
		cache.saveDNSCacheAccess.RUnlock()
		cache.saveRDRCAccess.RLock()
		rdrcEmpty := len(cache.saveRDRC) == 0
		cache.saveRDRCAccess.RUnlock()
		cache.saveFakeIPAccess.RLock()
		fakeEmpty := len(cache.saveDomain) == 0
		cache.saveFakeIPAccess.RUnlock()
		cache.saveMetadataAccess.Lock()
		metadataEmpty := cache.saveMetadata == nil
		cache.saveMetadataAccess.Unlock()
		return dnsEmpty && rdrcEmpty && fakeEmpty && metadataEmpty
	}, 4*time.Second, time.Millisecond)
	raw, expires, loaded := cache.LoadDNSCache("dns", "example.com.", 1)
	require.True(t, loaded)
	require.Equal(t, []byte("answer"), raw)
	require.Equal(t, expireAt.Unix(), expires.Unix())
	require.True(t, cache.LoadRDRC("dns", "blocked.example.", 1))
	domain, loaded = cache.FakeIPLoad(address)
	require.True(t, loaded)
	require.Equal(t, "fake.example", domain)
	require.Equal(t, metadata, cache.FakeIPMetadata())
}

func TestRDRCFailureDoesNotExtendExpiry(t *testing.T) {
	cache, log, recoverDB := newRetryTestCache(t)
	cache.rdrcTimeout = 20 * time.Millisecond
	cache.SaveRDRCAsync("dns", "expired.example.", 1, log)
	require.Eventually(t, func() bool { return log.failures.Load() > 0 }, time.Second, time.Millisecond)
	require.Eventually(t, func() bool { return !cache.LoadRDRC("dns", "expired.example.", 1) }, time.Second, time.Millisecond)
	recoverDB()
	cache.stopCacheWriter()
	require.False(t, cache.LoadRDRC("dns", "expired.example.", 1))
}

func TestCacheRetryKeepsLatestFakeIPMappingAndReset(t *testing.T) {
	cache, log, recoverDB := newRetryTestCache(t)
	oldAddress, newAddress := netip.MustParseAddr("198.18.0.1"), netip.MustParseAddr("198.18.0.2")
	cache.FakeIPStoreAsync(oldAddress, "example.com", log)
	require.Eventually(t, func() bool { return log.failures.Load() > 0 }, time.Second, time.Millisecond)
	cache.FakeIPStoreAsync(newAddress, "example.com", log)
	recoverDB()
	cache.stopCacheWriter()
	address, loaded := cache.FakeIPLoadDomain("example.com", false)
	require.True(t, loaded)
	require.Equal(t, newAddress, address)
	_, loaded = cache.FakeIPLoad(oldAddress)
	require.False(t, loaded)
	require.NoError(t, cache.FakeIPReset())
	cache.flushCacheWrites(true)
	_, loaded = cache.FakeIPLoad(newAddress)
	require.False(t, loaded)
}

func TestCacheResetDiscardsFailedWrites(t *testing.T) {
	cache, log, recoverDB := newRetryTestCache(t)
	address := netip.MustParseAddr("198.18.0.1")
	cache.SaveDNSCacheAsync("dns", "example.com.", 1, []byte("answer"), time.Now().Add(time.Hour), log)
	cache.FakeIPStoreAsync(address, "fake.example", log)
	require.Eventually(t, func() bool { return log.failures.Load() >= 2 }, time.Second, time.Millisecond)
	require.Error(t, cache.ClearDNSCache())
	require.Error(t, cache.FakeIPReset())
	recoverDB()
	cache.stopCacheWriter()
	_, _, loaded := cache.LoadDNSCache("dns", "example.com.", 1)
	require.False(t, loaded)
	_, loaded = cache.FakeIPLoad(address)
	require.False(t, loaded)
}

func TestSynchronousFakeIPSaveSupersedesFailedAsyncWrite(t *testing.T) {
	cache, log, recoverDB := newRetryTestCache(t)
	address := netip.MustParseAddr("198.18.0.1")
	oldMetadata := &adapter.FakeIPMetadata{Inet4Range: netip.MustParsePrefix("198.18.0.0/15"), Inet4Current: address}
	cache.FakeIPStoreAsync(address, "old.example", log)
	cache.FakeIPSaveMetadataAsync(oldMetadata)
	require.Eventually(t, func() bool { return log.failures.Load() > 0 }, time.Second, time.Millisecond)
	recoverDB()
	newMetadata := *oldMetadata
	newMetadata.Inet4Current = address.Next()
	require.NoError(t, cache.FakeIPStore(address, "new.example"))
	require.NoError(t, cache.FakeIPSaveMetadata(&newMetadata))
	cache.stopCacheWriter()
	domain, loaded := cache.FakeIPLoad(address)
	require.True(t, loaded)
	require.Equal(t, "new.example", domain)
	_, loaded = cache.FakeIPLoadDomain("old.example", false)
	require.False(t, loaded)
	require.Equal(t, &newMetadata, cache.FakeIPMetadata())
}

func TestSynchronousFakeIPFailureIsRetried(t *testing.T) {
	cache, _, recoverDB := newRetryTestCache(t)
	address := netip.MustParseAddr("198.18.0.1")
	metadata := &adapter.FakeIPMetadata{Inet4Range: netip.MustParsePrefix("198.18.0.0/15"), Inet4Current: address}
	require.Error(t, cache.FakeIPStore(address, "sync.example"))
	require.Error(t, cache.FakeIPSaveMetadata(metadata))
	domain, loaded := cache.FakeIPLoad(address)
	require.True(t, loaded)
	require.Equal(t, "sync.example", domain)
	recoverDB()
	cache.stopCacheWriter()
	domain, loaded = cache.FakeIPLoad(address)
	require.True(t, loaded)
	require.Equal(t, "sync.example", domain)
	require.Equal(t, metadata, cache.FakeIPMetadata())
}
