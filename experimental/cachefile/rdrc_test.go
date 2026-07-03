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
	"github.com/sagernet/sing/common/buf"
	"github.com/stretchr/testify/require"
)

func TestEncodeRDRCKeyPreservesLegacyKey(t *testing.T) {
	t.Parallel()

	key := adapter.DNSCacheKey{
		TransportName: "local",
		QuestionName:  "example.com.",
		QType:         1,
	}
	encoded := encodeRDRCKey(key)
	defer buf.Put(encoded)
	require.Equal(t, key.QType, binary.BigEndian.Uint16(encoded))
	require.Equal(t, key.QuestionName, string(encoded[2:]))
	require.Equal(t, bucketRDRC, rdrcBucket(key))
}

func TestEncodeRDRCKeySeparatesClientSubnets(t *testing.T) {
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
	encodedA := encodeRDRCKey(normalizeRDRCKey(keyA))
	defer buf.Put(encodedA)
	encodedANormalized := encodeRDRCKey(normalizeRDRCKey(keyANormalized))
	defer buf.Put(encodedANormalized)
	encodedB := encodeRDRCKey(normalizeRDRCKey(keyB))
	defer buf.Put(encodedB)

	require.Equal(t, encodedA, encodedANormalized)
	require.NotEqual(t, encodedA, encodedB)
	require.Equal(t, bucketRDRCECS, rdrcBucket(keyA))
}

func TestRDRCStoreSeparatesClientSubnetsAndReadsLegacyDatabase(t *testing.T) {
	t.Parallel()

	database, err := bbolt.Open(filepath.Join(t.TempDir(), "cache.db"), 0o600, nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, database.Close()) })
	cache := &CacheFile{
		rdrcTimeout: time.Hour,
		DB:          database,
		saveRDRC:    make(map[adapter.DNSCacheKey]bool),
	}
	base := adapter.DNSCacheKey{
		TransportName: "local",
		QuestionName:  "example.com.",
		QType:         1,
	}
	legacyKey := make([]byte, 2+len(base.QuestionName))
	binary.BigEndian.PutUint16(legacyKey, base.QType)
	copy(legacyKey[2:], base.QuestionName)
	expiresAt := make([]byte, 8)
	binary.BigEndian.PutUint64(expiresAt, uint64(time.Now().Add(time.Hour).Unix()))
	require.NoError(t, database.Update(func(tx *bbolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists(bucketRDRC)
		if err != nil {
			return err
		}
		bucket, err = bucket.CreateBucketIfNotExists([]byte(base.TransportName))
		if err != nil {
			return err
		}
		return bucket.Put(legacyKey, expiresAt)
	}))

	keyA := base
	keyA.ClientSubnet = netip.MustParsePrefix("1.1.1.123/24")
	keyANormalized := base
	keyANormalized.ClientSubnet = netip.MustParsePrefix("1.1.1.0/24")
	keyB := base
	keyB.ClientSubnet = netip.MustParsePrefix("2.2.2.0/24")

	require.NoError(t, cache.SaveRDRCWithKey(keyA))
	require.NoError(t, cache.SaveRDRCWithKey(keyB))
	require.True(t, cache.LoadRDRC(base.TransportName, base.QuestionName, base.QType))
	require.True(t, cache.LoadRDRCWithKey(keyANormalized))
	require.True(t, cache.LoadRDRCWithKey(keyB))

	missing := base
	missing.ClientSubnet = netip.MustParsePrefix("3.3.3.0/24")
	require.False(t, cache.LoadRDRCWithKey(missing))
	require.Equal(t, bucketRDRCECS, rdrcBucket(keyA))
}

func TestSaveRDRCCleansExpiredLegacyAndECSRecords(t *testing.T) {
	t.Parallel()

	database, err := bbolt.Open(filepath.Join(t.TempDir(), "cache.db"), 0o600, nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, database.Close()) })
	cache := &CacheFile{
		rdrcTimeout: time.Hour,
		DB:          database,
		saveRDRC:    make(map[adapter.DNSCacheKey]bool),
	}
	now := time.Now()
	expiredLegacy := adapter.DNSCacheKey{TransportName: "expired-legacy", QuestionName: "example.com.", QType: 1}
	validLegacy := adapter.DNSCacheKey{TransportName: "valid-legacy", QuestionName: "example.com.", QType: 1}
	expiredECS := adapter.DNSCacheKey{
		TransportName: "expired-ecs",
		QuestionName:  "example.com.",
		QType:         1,
		ClientSubnet:  netip.MustParsePrefix("1.1.1.0/24"),
	}
	validECS := adapter.DNSCacheKey{
		TransportName: "valid-ecs",
		QuestionName:  "example.com.",
		QType:         1,
		ClientSubnet:  netip.MustParsePrefix("2.2.2.0/24"),
	}
	putEntry := func(key adapter.DNSCacheKey, expiresAt time.Time) {
		key = normalizeRDRCKey(key)
		encodedKey := encodeRDRCKey(key)
		defer buf.Put(encodedKey)
		content := make([]byte, 8)
		binary.BigEndian.PutUint64(content, uint64(expiresAt.Unix()))
		require.NoError(t, database.Update(func(tx *bbolt.Tx) error {
			bucket, err := tx.CreateBucketIfNotExists(rdrcBucket(key))
			if err != nil {
				return err
			}
			bucket, err = bucket.CreateBucketIfNotExists([]byte(key.TransportName))
			if err != nil {
				return err
			}
			return bucket.Put(encodedKey, content)
		}))
	}
	putEntry(expiredLegacy, now.Add(-time.Hour))
	putEntry(validLegacy, now.Add(time.Hour))
	putEntry(expiredECS, now.Add(-time.Hour))
	putEntry(validECS, now.Add(time.Hour))

	require.NoError(t, cache.SaveRDRC("trigger", "example.com.", 1))
	require.NoError(t, database.View(func(tx *bbolt.Tx) error {
		legacyBucket := tx.Bucket(bucketRDRC)
		require.NotNil(t, legacyBucket)
		require.Nil(t, legacyBucket.Bucket([]byte(expiredLegacy.TransportName)))
		require.NotNil(t, legacyBucket.Bucket([]byte(validLegacy.TransportName)))
		ecsBucket := tx.Bucket(bucketRDRCECS)
		require.NotNil(t, ecsBucket)
		require.Nil(t, ecsBucket.Bucket([]byte(expiredECS.TransportName)))
		require.NotNil(t, ecsBucket.Bucket([]byte(validECS.TransportName)))
		return nil
	}))
}

func TestDeleteExpiredRDRCRechecksCurrentValue(t *testing.T) {
	t.Parallel()

	database, err := bbolt.Open(filepath.Join(t.TempDir(), "cache.db"), 0o600, nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, database.Close()) })
	cache := &CacheFile{DB: database, saveRDRC: make(map[adapter.DNSCacheKey]bool)}
	key := normalizeRDRCKey(adapter.DNSCacheKey{
		TransportName: "local",
		QuestionName:  "example.com.",
		QType:         1,
		ClientSubnet:  netip.MustParsePrefix("1.1.1.0/24"),
	})
	encodedKey := encodeRDRCKey(key)
	defer buf.Put(encodedKey)
	putValue := func(value []byte) {
		t.Helper()
		require.NoError(t, database.Update(func(tx *bbolt.Tx) error {
			bucket, err := tx.CreateBucketIfNotExists(rdrcBucket(key))
			if err != nil {
				return err
			}
			bucket, err = bucket.CreateBucketIfNotExists([]byte(key.TransportName))
			if err != nil {
				return err
			}
			return bucket.Put(encodedKey, value)
		}))
	}
	hasValue := func() bool {
		t.Helper()
		var loaded bool
		require.NoError(t, database.View(func(tx *bbolt.Tx) error {
			bucket := tx.Bucket(rdrcBucket(key))
			if bucket != nil {
				bucket = bucket.Bucket([]byte(key.TransportName))
			}
			loaded = bucket != nil && bucket.Get(encodedKey) != nil
			return nil
		}))
		return loaded
	}
	expiresAt := func(value time.Time) []byte {
		content := make([]byte, 8)
		binary.BigEndian.PutUint64(content, uint64(value.Unix()))
		return content
	}

	putValue(expiresAt(time.Now().Add(time.Hour)))
	require.NoError(t, cache.deleteExpiredRDRC(key, encodedKey))
	require.True(t, hasValue())

	putValue(expiresAt(time.Now().Add(-time.Hour)))
	require.NoError(t, cache.deleteExpiredRDRC(key, encodedKey))
	require.False(t, hasValue())

	putValue([]byte{1})
	require.False(t, cache.LoadRDRCWithKey(key))
	require.False(t, hasValue())
}

func TestRDRCSaveQueueIsBoundedAndDeduplicated(t *testing.T) {
	t.Parallel()

	cache := &CacheFile{
		saveRDRC:      make(map[adapter.DNSCacheKey]bool),
		saveRDRCQueue: make(chan saveRDRCRequest, 1),
	}
	firstKey := adapter.DNSCacheKey{TransportName: "local", QuestionName: "first.example.", QType: 1}
	secondKey := adapter.DNSCacheKey{TransportName: "local", QuestionName: "second.example.", QType: 1}

	cache.queueRDRCSave(saveRDRCRequest{key: firstKey})
	cache.queueRDRCSave(saveRDRCRequest{key: firstKey})
	cache.queueRDRCSave(saveRDRCRequest{key: secondKey})

	require.Len(t, cache.saveRDRCQueue, 1)
	require.True(t, cache.saveRDRC[firstKey])
	require.False(t, cache.saveRDRC[secondKey])
}

func TestRDRCPendingLimitIncludesInFlightRequests(t *testing.T) {
	t.Parallel()

	cache := &CacheFile{
		saveRDRC:      make(map[adapter.DNSCacheKey]bool),
		saveRDRCQueue: make(chan saveRDRCRequest, rdrcSaveQueueSize+1),
	}
	for index := range rdrcSaveQueueSize {
		cache.queueRDRCSave(saveRDRCRequest{key: adapter.DNSCacheKey{
			TransportName: "local",
			QuestionName:  fmt.Sprintf("%d.example.", index),
			QType:         1,
		}})
	}
	<-cache.saveRDRCQueue
	extraKey := adapter.DNSCacheKey{TransportName: "local", QuestionName: "extra.example.", QType: 1}
	cache.queueRDRCSave(saveRDRCRequest{key: extraKey})

	require.Len(t, cache.saveRDRC, rdrcSaveQueueSize)
	require.Len(t, cache.saveRDRCQueue, rdrcSaveQueueSize-1)
	require.False(t, cache.saveRDRC[extraKey])
}

func TestRDRCSaveQueueFlushesBatch(t *testing.T) {
	t.Parallel()

	database, err := bbolt.Open(filepath.Join(t.TempDir(), "cache.db"), 0o600, nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, database.Close()) })
	ctx, cancel := context.WithCancel(context.Background())
	cache := &CacheFile{
		ctx:           ctx,
		rdrcTimeout:   time.Hour,
		DB:            database,
		saveRDRC:      make(map[adapter.DNSCacheKey]bool),
		saveRDRCQueue: make(chan saveRDRCRequest, 4),
	}
	keys := []adapter.DNSCacheKey{
		{TransportName: "local", QuestionName: "first.example.", QType: 1},
		{TransportName: "local", QuestionName: "second.example.", QType: 1, ClientSubnet: netip.MustParsePrefix("1.1.1.0/24")},
		{TransportName: "remote", QuestionName: "third.example.", QType: 28, ClientSubnet: netip.MustParsePrefix("2001:db8::/48")},
	}
	for _, key := range keys {
		cache.SaveRDRCAsyncWithKey(key, nil)
	}
	done := make(chan struct{})
	go func() {
		cache.loopRDRCSave()
		close(done)
	}()

	require.Eventually(t, func() bool {
		for _, key := range keys {
			cache.saveRDRCAccess.RLock()
			pending := cache.saveRDRC[normalizeRDRCKey(key)]
			cache.saveRDRCAccess.RUnlock()
			if pending || !cache.LoadRDRCWithKey(key) {
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

func TestCleanupUnknownBucketsPreservesRDRCECS(t *testing.T) {
	t.Parallel()

	database, err := bbolt.Open(filepath.Join(t.TempDir(), "cache.db"), 0o600, nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, database.Close()) })
	cacheID := []byte{0, 't', 'e', 's', 't'}
	unknownBucket := []byte("unknown")
	require.NoError(t, database.Update(func(tx *bbolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(bucketRDRCECS)
		if err != nil {
			return err
		}
		_, err = tx.CreateBucketIfNotExists(unknownBucket)
		if err != nil {
			return err
		}
		root, err := tx.CreateBucketIfNotExists(cacheID)
		if err != nil {
			return err
		}
		_, err = root.CreateBucketIfNotExists(bucketRDRCECS)
		if err != nil {
			return err
		}
		_, err = root.CreateBucketIfNotExists(unknownBucket)
		if err != nil {
			return err
		}
		return cleanupUnknownBuckets(tx)
	}))

	require.NoError(t, database.View(func(tx *bbolt.Tx) error {
		require.NotNil(t, tx.Bucket(bucketRDRCECS))
		require.Nil(t, tx.Bucket(unknownBucket))
		root := tx.Bucket(cacheID)
		require.NotNil(t, root)
		require.NotNil(t, root.Bucket(bucketRDRCECS))
		require.Nil(t, root.Bucket(unknownBucket))
		return nil
	}))
}
