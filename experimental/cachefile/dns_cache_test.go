package cachefile

import (
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/sagernet/bbolt"
	"github.com/sagernet/sing-box/adapter"
	"github.com/stretchr/testify/require"
)

func TestEncodeDNSCacheKeyPreservesLegacyKey(t *testing.T) {
	t.Parallel()

	key := adapter.DNSCacheKey{
		TransportName: "local",
		QuestionName:  "example.com.",
		QType:         1,
	}
	encoded := encodeDNSCacheKey(key)
	require.Equal(t, key.QType, binary.BigEndian.Uint16(encoded))
	require.Equal(t, key.QuestionName, string(encoded[2:]))
	require.Equal(t, bucketDNSCache, dnsCacheBucket(key))
}

func TestEncodeDNSCacheKeySeparatesClientSubnets(t *testing.T) {
	t.Parallel()

	base := adapter.DNSCacheKey{
		TransportName: "local",
		QuestionName:  "example.com.",
		QType:         1,
	}
	keyA := base
	keyA.ClientSubnet = netip.MustParsePrefix("1.1.1.123/24")
	keyANormalized := base
	keyANormalized.ClientSubnet = netip.MustParsePrefix("1.1.1.0/24")
	keyB := base
	keyB.ClientSubnet = netip.MustParsePrefix("2.2.2.0/24")

	require.Equal(t, encodeDNSCacheKey(normalizeDNSCacheKey(keyA)), encodeDNSCacheKey(normalizeDNSCacheKey(keyANormalized)))
	require.NotEqual(t, encodeDNSCacheKey(normalizeDNSCacheKey(keyA)), encodeDNSCacheKey(normalizeDNSCacheKey(keyB)))
	require.Equal(t, bucketDNSCacheECS, dnsCacheBucket(keyA))
}

func TestDNSCacheStoreSeparatesClientSubnets(t *testing.T) {
	t.Parallel()

	database, err := bbolt.Open(filepath.Join(t.TempDir(), "cache.db"), 0o600, nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, database.Close()) })
	cache := &CacheFile{
		DB:           database,
		saveDNSCache: make(map[adapter.DNSCacheKey]saveDNSCacheEntry),
	}
	base := adapter.DNSCacheKey{
		TransportName: "local",
		QuestionName:  "example.com.",
		QType:         1,
	}
	keyA := base
	keyA.ClientSubnet = netip.MustParsePrefix("1.1.1.123/24")
	keyANormalized := base
	keyANormalized.ClientSubnet = netip.MustParsePrefix("1.1.1.0/24")
	keyB := base
	keyB.ClientSubnet = netip.MustParsePrefix("2.2.2.0/24")
	expireAt := time.Now().Add(time.Hour).Truncate(time.Second)

	require.NoError(t, cache.SaveDNSCache(base.TransportName, base.QuestionName, base.QType, []byte("plain"), expireAt))
	require.NoError(t, cache.SaveDNSCacheWithKey(keyA, []byte("subnet-a"), expireAt))
	require.NoError(t, cache.SaveDNSCacheWithKey(keyB, []byte("subnet-b"), expireAt))

	plain, plainExpireAt, loaded := cache.LoadDNSCache(base.TransportName, base.QuestionName, base.QType)
	require.True(t, loaded)
	require.Equal(t, []byte("plain"), plain)
	require.Equal(t, expireAt, plainExpireAt)
	subnetA, _, loaded := cache.LoadDNSCacheWithKey(keyANormalized)
	require.True(t, loaded)
	require.Equal(t, []byte("subnet-a"), subnetA)
	subnetB, _, loaded := cache.LoadDNSCacheWithKey(keyB)
	require.True(t, loaded)
	require.Equal(t, []byte("subnet-b"), subnetB)

	require.NoError(t, cache.ClearDNSCache())
	_, _, loaded = cache.LoadDNSCacheWithKey(base)
	require.False(t, loaded)
	_, _, loaded = cache.LoadDNSCacheWithKey(keyA)
	require.False(t, loaded)
}

func TestDNSCacheSaveQueueCoalescesLatestEntry(t *testing.T) {
	t.Parallel()

	cache := &CacheFile{
		saveDNSCache:      make(map[adapter.DNSCacheKey]saveDNSCacheEntry),
		saveDNSCacheQueue: make(chan adapter.DNSCacheKey, 1),
	}
	key := adapter.DNSCacheKey{TransportName: "local", QuestionName: "example.com.", QType: 1}
	firstExpireAt := time.Now().Add(time.Minute)
	latestExpireAt := firstExpireAt.Add(time.Minute)

	cache.queueDNSCacheSave(key, []byte("first"), firstExpireAt, nil)
	cache.queueDNSCacheSave(key, []byte("latest"), latestExpireAt, nil)

	require.Len(t, cache.saveDNSCacheQueue, 1)
	entry := cache.saveDNSCache[key]
	require.Equal(t, []byte("latest"), entry.rawMessage)
	require.Equal(t, latestExpireAt, entry.expireAt)
}

func TestDNSCacheSaveQueueDropsNewEntryWhenFull(t *testing.T) {
	t.Parallel()

	cache := &CacheFile{
		saveDNSCache:      make(map[adapter.DNSCacheKey]saveDNSCacheEntry),
		saveDNSCacheQueue: make(chan adapter.DNSCacheKey, 1),
	}
	cache.saveDNSCacheQueue <- adapter.DNSCacheKey{QuestionName: "stale.example."}
	key := adapter.DNSCacheKey{TransportName: "local", QuestionName: "example.com.", QType: 1}

	cache.queueDNSCacheSave(key, []byte("response"), time.Now().Add(time.Hour), nil)

	require.Len(t, cache.saveDNSCacheQueue, 1)
	_, loaded := cache.saveDNSCache[key]
	require.False(t, loaded)
}

func TestDNSCachePendingLimitIncludesInFlightEntries(t *testing.T) {
	t.Parallel()

	cache := &CacheFile{
		saveDNSCache:      make(map[adapter.DNSCacheKey]saveDNSCacheEntry),
		saveDNSCacheQueue: make(chan adapter.DNSCacheKey, dnsCacheSaveQueueSize+1),
	}
	for index := range dnsCacheSaveQueueSize {
		cache.queueDNSCacheSave(adapter.DNSCacheKey{
			TransportName: "local",
			QuestionName:  fmt.Sprintf("%d.example.", index),
			QType:         1,
		}, []byte("response"), time.Now().Add(time.Hour), nil)
	}
	<-cache.saveDNSCacheQueue
	extraKey := adapter.DNSCacheKey{TransportName: "local", QuestionName: "extra.example.", QType: 1}
	cache.queueDNSCacheSave(extraKey, []byte("response"), time.Now().Add(time.Hour), nil)

	require.Len(t, cache.saveDNSCache, dnsCacheSaveQueueSize)
	require.Len(t, cache.saveDNSCacheQueue, dnsCacheSaveQueueSize-1)
	_, loaded := cache.saveDNSCache[extraKey]
	require.False(t, loaded)
}

func TestDNSCacheSaveQueueFlushesBatch(t *testing.T) {
	t.Parallel()

	database := openRDRCTestDatabase(t)
	ctx, cancel := context.WithCancel(context.Background())
	cache := &CacheFile{
		ctx:               ctx,
		DB:                database,
		saveDNSCache:      make(map[adapter.DNSCacheKey]saveDNSCacheEntry),
		saveDNSCacheQueue: make(chan adapter.DNSCacheKey, 4),
	}
	entries := []struct {
		key      adapter.DNSCacheKey
		response []byte
	}{
		{adapter.DNSCacheKey{TransportName: "local", QuestionName: "first.example.", QType: 1}, []byte("first")},
		{adapter.DNSCacheKey{TransportName: "local", QuestionName: "second.example.", QType: 1, ClientSubnet: netip.MustParsePrefix("1.1.1.0/24")}, []byte("second")},
		{adapter.DNSCacheKey{TransportName: "remote", QuestionName: "third.example.", QType: 28, ClientSubnet: netip.MustParsePrefix("2001:db8::/48")}, []byte("third")},
	}
	expireAt := time.Now().Add(time.Hour).Truncate(time.Second)
	for _, entry := range entries {
		cache.SaveDNSCacheAsyncWithKey(entry.key, entry.response, expireAt, nil)
	}
	done := make(chan struct{})
	go func() {
		cache.loopDNSCacheSave()
		close(done)
	}()

	require.Eventually(t, func() bool {
		for _, entry := range entries {
			cache.saveDNSCacheAccess.RLock()
			_, pending := cache.saveDNSCache[normalizeDNSCacheKey(entry.key)]
			cache.saveDNSCacheAccess.RUnlock()
			response, loadedExpireAt, loaded := cache.LoadDNSCacheWithKey(entry.key)
			if pending || !loaded || !loadedExpireAt.Equal(expireAt) || string(response) != string(entry.response) {
				return false
			}
		}
		return true
	}, time.Second, time.Millisecond)

	cancel()
	require.Eventually(t, func() bool {
		select {
		case <-done:
			return true
		default:
			return false
		}
	}, time.Second, time.Millisecond)
}

func TestDNSCacheSaveQueueKeepsLatestUpdateDuringFlush(t *testing.T) {
	t.Parallel()

	database := openRDRCTestDatabase(t)
	ctx, cancel := context.WithCancel(context.Background())
	cache := &CacheFile{
		ctx:               ctx,
		DB:                database,
		saveDNSCache:      make(map[adapter.DNSCacheKey]saveDNSCacheEntry),
		saveDNSCacheQueue: make(chan adapter.DNSCacheKey, 2),
	}
	key := adapter.DNSCacheKey{TransportName: "local", QuestionName: "example.com.", QType: 1}
	expireAt := time.Now().Add(time.Hour).Truncate(time.Second)
	cache.SaveDNSCacheAsyncWithKey(key, []byte("old"), expireAt, nil)

	writerStarted := make(chan struct{})
	releaseWriter := make(chan struct{})
	writerDone := make(chan error, 1)
	go func() {
		writerDone <- database.Update(func(*bbolt.Tx) error {
			close(writerStarted)
			<-releaseWriter
			return nil
		})
	}()
	<-writerStarted
	workerDone := make(chan struct{})
	go func() {
		cache.loopDNSCacheSave()
		close(workerDone)
	}()
	require.Eventually(t, func() bool {
		cache.saveDNSCacheAccess.RLock()
		entry := cache.saveDNSCache[key]
		cache.saveDNSCacheAccess.RUnlock()
		return entry.inFlight
	}, time.Second, time.Millisecond)

	cache.SaveDNSCacheAsyncWithKey(key, []byte("latest"), expireAt, nil)
	close(releaseWriter)
	require.NoError(t, <-writerDone)
	require.Eventually(t, func() bool {
		cache.saveDNSCacheAccess.RLock()
		_, pending := cache.saveDNSCache[key]
		cache.saveDNSCacheAccess.RUnlock()
		response, _, loaded := cache.LoadDNSCacheWithKey(key)
		return !pending && loaded && string(response) == "latest"
	}, time.Second, time.Millisecond)

	cancel()
	require.Eventually(t, func() bool {
		select {
		case <-workerDone:
			return true
		default:
			return false
		}
	}, time.Second, time.Millisecond)
}

func TestCleanupDNSCacheRemovesExpiredEntries(t *testing.T) {
	t.Parallel()

	database := openRDRCTestDatabase(t)
	cache := &CacheFile{DB: database}
	expiredKey := adapter.DNSCacheKey{TransportName: "local", QuestionName: "expired.example.", QType: 1}
	expiredECSKey := adapter.DNSCacheKey{
		TransportName: "local",
		QuestionName:  "expired-ecs.example.",
		QType:         1,
		ClientSubnet:  netip.MustParsePrefix("1.1.1.0/24"),
	}
	freshKey := adapter.DNSCacheKey{TransportName: "local", QuestionName: "fresh.example.", QType: 1}
	require.NoError(t, cache.SaveDNSCacheWithKey(expiredKey, []byte("expired"), time.Now().Add(-time.Hour)))
	require.NoError(t, cache.SaveDNSCacheWithKey(expiredECSKey, []byte("expired-ecs"), time.Now().Add(-time.Hour)))
	require.NoError(t, cache.SaveDNSCacheWithKey(freshKey, []byte("fresh"), time.Now().Add(time.Hour)))

	cache.cleanupDNSCache()

	_, _, loaded := cache.LoadDNSCacheWithKey(expiredKey)
	require.False(t, loaded)
	_, _, loaded = cache.LoadDNSCacheWithKey(expiredECSKey)
	require.False(t, loaded)
	response, _, loaded := cache.LoadDNSCacheWithKey(freshKey)
	require.True(t, loaded)
	require.Equal(t, []byte("fresh"), response)
}
