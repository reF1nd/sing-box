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

func openRDRCTestDatabase(t *testing.T) *bbolt.DB {
	t.Helper()
	database, err := bbolt.Open(filepath.Join(t.TempDir(), "cache.db"), 0o600, nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, database.Close()) })
	return database
}

func TestEncodeRDRCKeyMatchesStableFormat(t *testing.T) {
	t.Parallel()

	encoded := encodeRDRCKey(adapter.DNSCacheKey{
		QuestionName: "a.",
		QType:        1,
		ClientSubnet: netip.MustParsePrefix("1.2.3.0/24"),
	})
	require.Equal(t, []byte{
		0, 1,
		0, 2,
		'a', '.',
		4, 24,
		1, 2, 3, 0,
	}, encoded)
}

func TestStoreDNSSupersedesRDRC(t *testing.T) {
	t.Parallel()

	require.True(t, (&CacheFile{storeRDRC: true}).StoreRDRC())
	require.False(t, (&CacheFile{storeRDRC: true, storeDNS: true}).StoreRDRC())
}

func TestRDRCStoreReadsStableClientSubnetBucket(t *testing.T) {
	t.Parallel()

	database := openRDRCTestDatabase(t)
	cache := &CacheFile{
		rdrcTimeout: time.Hour,
		DB:          database,
		saveRDRC:    make(map[adapter.DNSCacheKey]bool),
	}
	key := adapter.DNSCacheKey{
		TransportName: "local",
		QuestionName:  "example.com.",
		QType:         1,
		ClientSubnet:  netip.MustParsePrefix("1.1.1.123/24"),
	}
	normalizedKey := normalizeRDRCKey(key)
	encodedKey := encodeRDRCKey(normalizedKey)
	expiresAt := make([]byte, 8)
	binary.BigEndian.PutUint64(expiresAt, uint64(time.Now().Add(time.Hour).Unix()))
	require.NoError(t, database.Update(func(tx *bbolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists(bucketRDRCECS)
		if err != nil {
			return err
		}
		bucket, err = bucket.CreateBucketIfNotExists([]byte(key.TransportName))
		if err != nil {
			return err
		}
		return bucket.Put(encodedKey, expiresAt)
	}))

	require.True(t, cache.LoadRDRCWithKey(normalizedKey))
	missing := normalizedKey
	missing.ClientSubnet = netip.MustParsePrefix("2.2.2.0/24")
	require.False(t, cache.LoadRDRCWithKey(missing))
}

func TestDeleteExpiredRDRCRechecksCurrentValue(t *testing.T) {
	t.Parallel()

	database := openRDRCTestDatabase(t)
	cache := &CacheFile{DB: database}
	key := normalizeRDRCKey(adapter.DNSCacheKey{
		TransportName: "local",
		QuestionName:  "example.com.",
		QType:         1,
		ClientSubnet:  netip.MustParsePrefix("1.1.1.0/24"),
	})
	encodedKey := encodeRDRCKey(key)
	putValue := func(expiresAt time.Time) {
		t.Helper()
		value := make([]byte, 8)
		binary.BigEndian.PutUint64(value, uint64(expiresAt.Unix()))
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

	putValue(time.Now().Add(time.Hour))
	require.NoError(t, cache.deleteExpiredRDRC(key, encodedKey))
	require.True(t, hasValue())

	putValue(time.Now().Add(-time.Hour))
	require.NoError(t, cache.deleteExpiredRDRC(key, encodedKey))
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

func TestRDRCSaveQueueFlushes(t *testing.T) {
	t.Parallel()

	database := openRDRCTestDatabase(t)
	ctx, cancel := context.WithCancel(context.Background())
	cache := &CacheFile{
		ctx:           ctx,
		rdrcTimeout:   time.Hour,
		DB:            database,
		saveRDRC:      make(map[adapter.DNSCacheKey]bool),
		saveRDRCQueue: make(chan saveRDRCRequest, 4),
	}
	keys := []adapter.DNSCacheKey{
		{TransportName: "local", QuestionName: "first.example.", QType: 1, ClientSubnet: netip.MustParsePrefix("1.1.1.0/24")},
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

func TestCleanupUnknownBucketsPreservesStableRDRCECS(t *testing.T) {
	t.Parallel()

	database := openRDRCTestDatabase(t)
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

func TestClearRDRCRemovesLegacyAndClientSubnetBuckets(t *testing.T) {
	for _, withCacheID := range []bool{false, true} {
		withCacheID := withCacheID
		t.Run(map[bool]string{false: "default", true: "cache-id"}[withCacheID], func(t *testing.T) {
			t.Parallel()

			database := openRDRCTestDatabase(t)
			cache := &CacheFile{
				DB:       database,
				saveRDRC: make(map[adapter.DNSCacheKey]bool),
			}
			if withCacheID {
				cache.cacheID = []byte{0, 't', 'e', 's', 't'}
			}
			require.NoError(t, database.Update(func(tx *bbolt.Tx) error {
				var root interface {
					CreateBucketIfNotExists(name []byte) (*bbolt.Bucket, error)
				}
				if cache.cacheID == nil {
					root = tx
				} else {
					bucket, err := tx.CreateBucketIfNotExists(cache.cacheID)
					if err != nil {
						return err
					}
					root = bucket
				}
				for _, bucketName := range [][]byte{bucketRDRC, bucketRDRCECS} {
					_, err := root.CreateBucketIfNotExists(bucketName)
					if err != nil {
						return err
					}
				}
				return nil
			}))

			cache.clearRDRC()
			require.NoError(t, database.View(func(tx *bbolt.Tx) error {
				if cache.cacheID == nil {
					require.Nil(t, tx.Bucket(bucketRDRC))
					require.Nil(t, tx.Bucket(bucketRDRCECS))
				} else {
					root := tx.Bucket(cache.cacheID)
					require.NotNil(t, root)
					require.Nil(t, root.Bucket(bucketRDRC))
					require.Nil(t, root.Bucket(bucketRDRCECS))
				}
				return nil
			}))
		})
	}
}
