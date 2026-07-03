package cachefile

import (
	"encoding/binary"
	"time"

	"github.com/sagernet/bbolt"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/logger"
)

var (
	bucketRDRC    = []byte("rdrc2")
	bucketRDRCECS = []byte("rdrc_ecs_v1")
)

const (
	rdrcSaveQueueSize = 1024
	rdrcSaveBatchSize = 128
)

type saveRDRCRequest struct {
	key    adapter.DNSCacheKey
	logger logger.Logger
}

func normalizeRDRCKey(key adapter.DNSCacheKey) adapter.DNSCacheKey {
	if key.ClientSubnet.IsValid() {
		key.ClientSubnet = key.ClientSubnet.Masked()
	}
	return key
}

func rdrcBucket(key adapter.DNSCacheKey) []byte {
	if key.ClientSubnet.IsValid() {
		return bucketRDRCECS
	}
	return bucketRDRC
}

func encodeRDRCKey(key adapter.DNSCacheKey) []byte {
	if !key.ClientSubnet.IsValid() {
		encoded := buf.Get(2 + len(key.QuestionName))
		binary.BigEndian.PutUint16(encoded, key.QType)
		copy(encoded[2:], key.QuestionName)
		return encoded
	}
	address := key.ClientSubnet.Addr().AsSlice()
	encoded := buf.Get(2 + 2 + len(key.QuestionName) + 1 + 1 + len(address))
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

func (c *CacheFile) shouldCleanupRDRC(now time.Time) bool {
	c.rdrcCleanupAccess.Lock()
	defer c.rdrcCleanupAccess.Unlock()
	if !c.rdrcNextCleanup.IsZero() && now.Before(c.rdrcNextCleanup) {
		return false
	}
	interval := c.rdrcTimeout
	if interval <= 0 || interval > time.Hour {
		interval = time.Hour
	}
	if interval < time.Minute {
		interval = time.Minute
	}
	c.rdrcNextCleanup = now.Add(interval)
	return true
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
		err := transportBucket.ForEach(func(key, content []byte) error {
			if content == nil {
				return nil
			}
			if len(content) < 8 || now.After(time.Unix(int64(binary.BigEndian.Uint64(content)), 0)) {
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
		key, _ := transportBucket.Cursor().First()
		if key == nil {
			emptyTransports = append(emptyTransports, append([]byte(nil), transportName...))
		}
		return nil
	})
	if err != nil {
		return err
	}
	for _, transportName := range emptyTransports {
		err = bucket.DeleteBucket(transportName)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *CacheFile) cleanupRDRC(tx *bbolt.Tx, now time.Time) error {
	for _, bucketName := range [][]byte{bucketRDRC, bucketRDRCECS} {
		err := c.cleanupRDRCBucket(tx, bucketName, now)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *CacheFile) StoreRDRC() bool {
	return c.storeRDRC
}

func (c *CacheFile) RDRCTimeout() time.Duration {
	return c.rdrcTimeout
}

func (c *CacheFile) LoadRDRC(transportName string, qName string, qType uint16) bool {
	return c.LoadRDRCWithKey(adapter.DNSCacheKey{
		TransportName: transportName,
		QuestionName:  qName,
		QType:         qType,
	})
}

func (c *CacheFile) LoadRDRCWithKey(key adapter.DNSCacheKey) (rejected bool) {
	key = normalizeRDRCKey(key)
	c.saveRDRCAccess.RLock()
	rejected, cached := c.saveRDRC[key]
	c.saveRDRCAccess.RUnlock()
	if cached {
		return
	}
	encodedKey := encodeRDRCKey(key)
	defer buf.Put(encodedKey)
	var deleteCache bool
	err := c.view(func(tx *bbolt.Tx) error {
		bucket := c.bucket(tx, rdrcBucket(key))
		if bucket == nil {
			return nil
		}
		bucket = bucket.Bucket([]byte(key.TransportName))
		if bucket == nil {
			return nil
		}
		content := bucket.Get(encodedKey)
		if len(content) < 8 {
			deleteCache = content != nil
			return nil
		}
		expiresAt := time.Unix(int64(binary.BigEndian.Uint64(content)), 0)
		if time.Now().After(expiresAt) {
			deleteCache = true
			return nil
		}
		rejected = true
		return nil
	})
	if err != nil {
		return false
	}
	if deleteCache {
		_ = c.deleteExpiredRDRC(key, encodedKey)
	}
	return
}

func (c *CacheFile) deleteExpiredRDRC(key adapter.DNSCacheKey, encodedKey []byte) error {
	return c.update(func(tx *bbolt.Tx) error {
		bucket := c.bucket(tx, rdrcBucket(key))
		if bucket == nil {
			return nil
		}
		bucket = bucket.Bucket([]byte(key.TransportName))
		if bucket == nil {
			return nil
		}
		content := bucket.Get(encodedKey)
		if content == nil {
			return nil
		}
		if len(content) >= 8 {
			expiresAt := time.Unix(int64(binary.BigEndian.Uint64(content)), 0)
			if !time.Now().After(expiresAt) {
				return nil
			}
		}
		return bucket.Delete(encodedKey)
	})
}

func (c *CacheFile) SaveRDRC(transportName string, qName string, qType uint16) error {
	return c.SaveRDRCWithKey(adapter.DNSCacheKey{
		TransportName: transportName,
		QuestionName:  qName,
		QType:         qType,
	})
}

func (c *CacheFile) SaveRDRCWithKey(key adapter.DNSCacheKey) error {
	key = normalizeRDRCKey(key)
	now := time.Now()
	cleanup := c.shouldCleanupRDRC(now)
	expiresAt := buf.Get(8)
	defer buf.Put(expiresAt)
	binary.BigEndian.PutUint64(expiresAt, uint64(now.Add(c.rdrcTimeout).Unix()))
	return c.batch(func(tx *bbolt.Tx) error {
		err := c.saveRDRCWithKey(tx, key, expiresAt)
		if err != nil || !cleanup {
			return err
		}
		return c.cleanupRDRC(tx, now)
	})
}

func (c *CacheFile) saveRDRCWithKey(tx *bbolt.Tx, key adapter.DNSCacheKey, expiresAt []byte) error {
	bucket, err := c.createBucket(tx, rdrcBucket(key))
	if err != nil {
		return err
	}
	bucket, err = bucket.CreateBucketIfNotExists([]byte(key.TransportName))
	if err != nil {
		return err
	}
	encodedKey := encodeRDRCKey(key)
	defer buf.Put(encodedKey)
	return bucket.Put(encodedKey, expiresAt)
}

func (c *CacheFile) SaveRDRCAsync(transportName string, qName string, qType uint16, logger logger.Logger) {
	c.SaveRDRCAsyncWithKey(adapter.DNSCacheKey{
		TransportName: transportName,
		QuestionName:  qName,
		QType:         qType,
	}, logger)
}

func (c *CacheFile) SaveRDRCAsyncWithKey(key adapter.DNSCacheKey, logger logger.Logger) {
	key = normalizeRDRCKey(key)
	c.queueRDRCSave(saveRDRCRequest{key: key, logger: logger})
}

func (c *CacheFile) queueRDRCSave(request saveRDRCRequest) {
	c.saveRDRCAccess.Lock()
	defer c.saveRDRCAccess.Unlock()
	if c.saveRDRC[request.key] || len(c.saveRDRC) >= rdrcSaveQueueSize {
		return
	}
	select {
	case c.saveRDRCQueue <- request:
		c.saveRDRC[request.key] = true
	default:
	}
}

func (c *CacheFile) loopRDRCSave() {
	for {
		select {
		case <-c.ctx.Done():
			return
		case request := <-c.saveRDRCQueue:
			requests := make([]saveRDRCRequest, 1, rdrcSaveBatchSize)
			requests[0] = request
		drainQueue:
			for len(requests) < rdrcSaveBatchSize {
				select {
				case request = <-c.saveRDRCQueue:
					requests = append(requests, request)
				default:
					break drainQueue
				}
			}
			c.flushRDRCSave(requests)
		}
	}
}

func (c *CacheFile) flushRDRCSave(requests []saveRDRCRequest) {
	now := time.Now()
	cleanup := c.shouldCleanupRDRC(now)
	expiresAt := make([]byte, 8)
	binary.BigEndian.PutUint64(expiresAt, uint64(now.Add(c.rdrcTimeout).Unix()))
	err := c.update(func(tx *bbolt.Tx) error {
		for _, request := range requests {
			err := c.saveRDRCWithKey(tx, request.key, expiresAt)
			if err != nil {
				return err
			}
		}
		if cleanup {
			return c.cleanupRDRC(tx, now)
		}
		return nil
	})
	if err != nil {
		for _, request := range requests {
			if request.logger != nil {
				request.logger.Warn("save RDRC: ", err)
				break
			}
		}
	}
	c.saveRDRCAccess.Lock()
	for _, request := range requests {
		delete(c.saveRDRC, request.key)
	}
	c.saveRDRCAccess.Unlock()
}
