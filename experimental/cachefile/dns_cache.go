package cachefile

import (
	"encoding/binary"
	"time"

	"github.com/sagernet/bbolt"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/logger"
)

var (
	bucketDNSCache    = []byte("dns_cache")
	bucketDNSCacheECS = []byte("dns_cache_ecs_v1")
)

const (
	dnsCacheSaveQueueSize = 1024
	dnsCacheSaveBatchSize = 128
)

type pendingDNSCacheSave struct {
	key   adapter.DNSCacheKey
	entry saveDNSCacheEntry
}

func (c *CacheFile) StoreDNS() bool {
	return c.storeDNS
}

func (c *CacheFile) LoadDNSCache(transportName string, qName string, qType uint16) (rawMessage []byte, expireAt time.Time, loaded bool) {
	return c.LoadDNSCacheWithKey(adapter.DNSCacheKey{
		TransportName: transportName,
		QuestionName:  qName,
		QType:         qType,
	})
}

func (c *CacheFile) SaveDNSCache(transportName string, qName string, qType uint16, rawMessage []byte, expireAt time.Time) error {
	return c.SaveDNSCacheWithKey(adapter.DNSCacheKey{
		TransportName: transportName,
		QuestionName:  qName,
		QType:         qType,
	}, rawMessage, expireAt)
}

func (c *CacheFile) SaveDNSCacheAsync(transportName string, qName string, qType uint16, rawMessage []byte, expireAt time.Time, logger logger.Logger) {
	c.SaveDNSCacheAsyncWithKey(adapter.DNSCacheKey{
		TransportName: transportName,
		QuestionName:  qName,
		QType:         qType,
	}, rawMessage, expireAt, logger)
}

func (c *CacheFile) DeleteDNSCache(transportName string, qName string, qType uint16) {
	c.DeleteDNSCacheWithKey(adapter.DNSCacheKey{
		TransportName: transportName,
		QuestionName:  qName,
		QType:         qType,
	})
}

func normalizeDNSCacheKey(key adapter.DNSCacheKey) adapter.DNSCacheKey {
	if key.ClientSubnet.IsValid() {
		key.ClientSubnet = key.ClientSubnet.Masked()
	}
	return key
}

func dnsCacheBucket(key adapter.DNSCacheKey) []byte {
	if key.ClientSubnet.IsValid() {
		return bucketDNSCacheECS
	}
	return bucketDNSCache
}

func encodeDNSCacheKey(key adapter.DNSCacheKey) []byte {
	if !key.ClientSubnet.IsValid() {
		encoded := make([]byte, 2+len(key.QuestionName))
		binary.BigEndian.PutUint16(encoded, key.QType)
		copy(encoded[2:], key.QuestionName)
		return encoded
	}
	address := key.ClientSubnet.Addr().AsSlice()
	encoded := make([]byte, 2+2+len(key.QuestionName)+1+1+len(address))
	binary.BigEndian.PutUint16(encoded, key.QType)
	binary.BigEndian.PutUint16(encoded[2:], uint16(len(key.QuestionName)))
	copy(encoded[4:], key.QuestionName)
	offset := 4 + len(key.QuestionName)
	if key.ClientSubnet.Addr().Is4() {
		encoded[offset] = 4
	} else {
		encoded[offset] = 6
	}
	encoded[offset+1] = byte(key.ClientSubnet.Bits())
	copy(encoded[offset+2:], address)
	return encoded
}

func (c *CacheFile) LoadDNSCacheWithKey(key adapter.DNSCacheKey) (rawMessage []byte, expireAt time.Time, loaded bool) {
	key = normalizeDNSCacheKey(key)
	c.saveDNSCacheAccess.RLock()
	entry, cached := c.saveDNSCache[key]
	c.saveDNSCacheAccess.RUnlock()
	if cached {
		return entry.rawMessage, entry.expireAt, true
	}
	encodedKey := encodeDNSCacheKey(key)
	err := c.view(func(tx *bbolt.Tx) error {
		bucket := c.bucket(tx, dnsCacheBucket(key))
		if bucket == nil {
			return nil
		}
		bucket = bucket.Bucket([]byte(key.TransportName))
		if bucket == nil {
			return nil
		}
		content := bucket.Get(encodedKey)
		if len(content) < 8 {
			return nil
		}
		expireAt = time.Unix(int64(binary.BigEndian.Uint64(content[:8])), 0)
		rawMessage = make([]byte, len(content)-8)
		copy(rawMessage, content[8:])
		loaded = true
		return nil
	})
	if err != nil {
		return nil, time.Time{}, false
	}
	return
}

func (c *CacheFile) SaveDNSCacheWithKey(key adapter.DNSCacheKey, rawMessage []byte, expireAt time.Time) error {
	key = normalizeDNSCacheKey(key)
	return c.batch(func(tx *bbolt.Tx) error {
		return c.saveDNSCacheWithKey(tx, key, rawMessage, expireAt)
	})
}

func (c *CacheFile) saveDNSCacheWithKey(tx *bbolt.Tx, key adapter.DNSCacheKey, rawMessage []byte, expireAt time.Time) error {
	// bbolt retains the value slice until the transaction commits.
	value := make([]byte, 8+len(rawMessage))
	binary.BigEndian.PutUint64(value[:8], uint64(expireAt.Unix()))
	copy(value[8:], rawMessage)
	bucket, err := c.createBucket(tx, dnsCacheBucket(key))
	if err != nil {
		return err
	}
	bucket, err = bucket.CreateBucketIfNotExists([]byte(key.TransportName))
	if err != nil {
		return err
	}
	return bucket.Put(encodeDNSCacheKey(key), value)
}

func (c *CacheFile) DeleteDNSCacheWithKey(key adapter.DNSCacheKey) {
	key = normalizeDNSCacheKey(key)
	c.saveDNSCacheAccess.Lock()
	delete(c.saveDNSCache, key)
	c.saveDNSCacheAccess.Unlock()
	_ = c.deleteDNSCacheWithKey(key)
}

func (c *CacheFile) deleteDNSCacheWithKey(key adapter.DNSCacheKey) error {
	encodedKey := encodeDNSCacheKey(key)
	return c.update(func(tx *bbolt.Tx) error {
		bucket := c.bucket(tx, dnsCacheBucket(key))
		if bucket == nil {
			return nil
		}
		bucket = bucket.Bucket([]byte(key.TransportName))
		if bucket == nil {
			return nil
		}
		return bucket.Delete(encodedKey)
	})
}

func (c *CacheFile) SaveDNSCacheAsyncWithKey(key adapter.DNSCacheKey, rawMessage []byte, expireAt time.Time, logger logger.Logger) {
	key = normalizeDNSCacheKey(key)
	c.queueDNSCacheSave(key, rawMessage, expireAt, logger)
}

func (c *CacheFile) queueDNSCacheSave(saveKey adapter.DNSCacheKey, rawMessage []byte, expireAt time.Time, saveLogger logger.Logger) {
	c.saveDNSCacheAccess.Lock()
	defer c.saveDNSCacheAccess.Unlock()
	entry, loaded := c.saveDNSCache[saveKey]
	if !loaded && len(c.saveDNSCache) >= dnsCacheSaveQueueSize {
		return
	}
	entry.rawMessage = append([]byte(nil), rawMessage...)
	entry.expireAt = expireAt
	c.saveDNSCacheSeq++
	entry.sequence = c.saveDNSCacheSeq
	entry.logger = saveLogger
	if !entry.queued && !entry.inFlight {
		select {
		case c.saveDNSCacheQueue <- saveKey:
			entry.queued = true
		default:
			if loaded {
				delete(c.saveDNSCache, saveKey)
			}
			return
		}
	}
	c.saveDNSCache[saveKey] = entry
}

func (c *CacheFile) loopDNSCacheSave() {
	for {
		select {
		case <-c.ctx.Done():
			return
		case key := <-c.saveDNSCacheQueue:
			keys := make([]adapter.DNSCacheKey, 1, dnsCacheSaveBatchSize)
			keys[0] = key
		drainQueue:
			for len(keys) < dnsCacheSaveBatchSize {
				select {
				case key = <-c.saveDNSCacheQueue:
					keys = append(keys, key)
				default:
					break drainQueue
				}
			}
			c.flushDNSCacheSave(keys)
		}
	}
}

func (c *CacheFile) flushDNSCacheSave(keys []adapter.DNSCacheKey) {
	c.saveDNSCacheAccess.Lock()
	requests := make([]pendingDNSCacheSave, 0, len(keys))
	for _, key := range keys {
		entry, loaded := c.saveDNSCache[key]
		if !loaded || !entry.queued {
			continue
		}
		entry.queued = false
		entry.inFlight = true
		c.saveDNSCache[key] = entry
		requests = append(requests, pendingDNSCacheSave{key: key, entry: entry})
	}
	c.saveDNSCacheAccess.Unlock()
	if len(requests) == 0 {
		return
	}
	err := c.update(func(tx *bbolt.Tx) error {
		for _, request := range requests {
			err := c.saveDNSCacheWithKey(tx, request.key, request.entry.rawMessage, request.entry.expireAt)
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		for _, request := range requests {
			if request.entry.logger != nil {
				request.entry.logger.Warn("save DNS cache: ", err)
				break
			}
		}
	}
	var canceledKeys []adapter.DNSCacheKey
	c.saveDNSCacheAccess.Lock()
	for _, request := range requests {
		currentEntry, loaded := c.saveDNSCache[request.key]
		if !loaded {
			canceledKeys = append(canceledKeys, request.key)
			continue
		}
		if currentEntry.sequence == request.entry.sequence {
			delete(c.saveDNSCache, request.key)
			continue
		}
		if currentEntry.inFlight {
			currentEntry.inFlight = false
			if !currentEntry.queued {
				select {
				case c.saveDNSCacheQueue <- request.key:
					currentEntry.queued = true
				default:
					delete(c.saveDNSCache, request.key)
					continue
				}
			}
			c.saveDNSCache[request.key] = currentEntry
		}
	}
	c.saveDNSCacheAccess.Unlock()
	for _, key := range canceledKeys {
		_ = c.deleteDNSCacheWithKey(key)
	}
}

func (c *CacheFile) ClearDNSCache() error {
	c.saveDNSCacheAccess.Lock()
	clear(c.saveDNSCache)
drainQueue:
	for {
		select {
		case <-c.saveDNSCacheQueue:
		default:
			break drainQueue
		}
	}
	c.saveDNSCacheAccess.Unlock()
	return c.batch(func(tx *bbolt.Tx) error {
		bucketNames := [][]byte{bucketDNSCache, bucketDNSCacheECS}
		if c.cacheID == nil {
			for _, bucketName := range bucketNames {
				if tx.Bucket(bucketName) != nil {
					err := tx.DeleteBucket(bucketName)
					if err != nil {
						return err
					}
				}
			}
			return nil
		}
		bucket := tx.Bucket(c.cacheID)
		if bucket == nil {
			return nil
		}
		for _, bucketName := range bucketNames {
			if bucket.Bucket(bucketName) != nil {
				err := bucket.DeleteBucket(bucketName)
				if err != nil {
					return err
				}
			}
		}
		return nil
	})
}

func (c *CacheFile) loopCacheCleanup(interval time.Duration, cleanupFunc func()) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			cleanupFunc()
		}
	}
}

func (c *CacheFile) cleanupDNSCache() {
	now := time.Now()
	err := c.batch(func(tx *bbolt.Tx) error {
		for _, bucketName := range [][]byte{bucketDNSCache, bucketDNSCacheECS} {
			err := c.cleanupDNSCacheBucket(tx, bucketName, now)
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		c.logger.Warn("cleanup DNS cache: ", err)
	}
}

func (c *CacheFile) cleanupDNSCacheBucket(tx *bbolt.Tx, bucketName []byte, now time.Time) error {
	bucket := c.bucket(tx, bucketName)
	if bucket == nil {
		return nil
	}
	var emptyTransports [][]byte
	err := bucket.ForEachBucket(func(transportName []byte) error {
		transportBucket := bucket.Bucket(transportName)
		if transportBucket == nil {
			return nil
		}
		var expiredKeys [][]byte
		err := transportBucket.ForEach(func(key, value []byte) error {
			if len(value) < 8 {
				expiredKeys = append(expiredKeys, append([]byte(nil), key...))
				return nil
			}
			if c.disableExpire {
				return nil
			}
			expireAt := time.Unix(int64(binary.BigEndian.Uint64(value[:8])), 0)
			if now.After(expireAt.Add(c.optimisticTimeout)) {
				expiredKeys = append(expiredKeys, append([]byte(nil), key...))
			}
			return nil
		})
		if err != nil {
			return err
		}
		for _, key := range expiredKeys {
			err = transportBucket.Delete(key)
			if err != nil {
				return err
			}
		}
		first, _ := transportBucket.Cursor().First()
		if first == nil {
			emptyTransports = append(emptyTransports, append([]byte(nil), transportName...))
		}
		return nil
	})
	if err != nil {
		return err
	}
	for _, name := range emptyTransports {
		err = bucket.DeleteBucket(name)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *CacheFile) clearRDRC() {
	c.saveRDRCAccess.Lock()
	clear(c.saveRDRC)
	c.saveRDRCAccess.Unlock()
	err := c.batch(func(tx *bbolt.Tx) error {
		bucketNames := [][]byte{bucketRDRC, bucketRDRCECS}
		if c.cacheID == nil {
			for _, bucketName := range bucketNames {
				if tx.Bucket(bucketName) != nil {
					err := tx.DeleteBucket(bucketName)
					if err != nil {
						return err
					}
				}
			}
			return nil
		}
		bucket := tx.Bucket(c.cacheID)
		if bucket == nil {
			return nil
		}
		for _, bucketName := range bucketNames {
			if bucket.Bucket(bucketName) != nil {
				err := bucket.DeleteBucket(bucketName)
				if err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		c.logger.Warn("clear RDRC: ", err)
	}
}

func (c *CacheFile) cleanupRDRC() {
	now := time.Now()
	err := c.batch(func(tx *bbolt.Tx) error {
		for _, bucketName := range [][]byte{bucketRDRC, bucketRDRCECS} {
			err := c.cleanupRDRCBucket(tx, bucketName, now)
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		c.logger.Warn("cleanup RDRC: ", err)
	}
}

func (c *CacheFile) cleanupRDRCBucket(tx *bbolt.Tx, bucketName []byte, now time.Time) error {
	bucket := c.bucket(tx, bucketName)
	if bucket == nil {
		return nil
	}
	var emptyTransports [][]byte
	err := bucket.ForEachBucket(func(transportName []byte) error {
		transportBucket := bucket.Bucket(transportName)
		if transportBucket == nil {
			return nil
		}
		var expiredKeys [][]byte
		err := transportBucket.ForEach(func(key, value []byte) error {
			if len(value) < 8 {
				expiredKeys = append(expiredKeys, append([]byte(nil), key...))
				return nil
			}
			expiresAt := time.Unix(int64(binary.BigEndian.Uint64(value)), 0)
			if now.After(expiresAt) {
				expiredKeys = append(expiredKeys, append([]byte(nil), key...))
			}
			return nil
		})
		if err != nil {
			return err
		}
		for _, key := range expiredKeys {
			err = transportBucket.Delete(key)
			if err != nil {
				return err
			}
		}
		first, _ := transportBucket.Cursor().First()
		if first == nil {
			emptyTransports = append(emptyTransports, append([]byte(nil), transportName...))
		}
		return nil
	})
	if err != nil {
		return err
	}
	for _, name := range emptyTransports {
		err = bucket.DeleteBucket(name)
		if err != nil {
			return err
		}
	}
	return nil
}
