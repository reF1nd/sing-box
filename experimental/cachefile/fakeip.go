package cachefile

import (
	"bytes"
	"net/netip"
	"os"
	"time"

	"github.com/sagernet/bbolt"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
)

const fakeipBucketPrefix = "fakeip_"

var (
	bucketFakeIP        = []byte(fakeipBucketPrefix + "address")
	bucketFakeIPDomain4 = []byte(fakeipBucketPrefix + "domain4")
	bucketFakeIPDomain6 = []byte(fakeipBucketPrefix + "domain6")
	keyMetadata         = []byte(fakeipBucketPrefix + "metadata")
)

func (c *CacheFile) FakeIPMetadata() *adapter.FakeIPMetadata {
	var metadata adapter.FakeIPMetadata
	err := c.batch(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(bucketFakeIP)
		if bucket == nil {
			return os.ErrNotExist
		}
		metadataBinary := bucket.Get(keyMetadata)
		if len(metadataBinary) == 0 {
			return os.ErrInvalid
		}
		err := bucket.Delete(keyMetadata)
		if err != nil {
			return err
		}
		return metadata.UnmarshalBinary(metadataBinary)
	})
	if err != nil {
		return nil
	}
	return &metadata
}

func (c *CacheFile) FakeIPSaveMetadata(metadata *adapter.FakeIPMetadata) error {
	c.cacheWriteAccess.Lock()
	defer c.cacheWriteAccess.Unlock()
	c.saveMetadataAccess.Lock()
	defer c.saveMetadataAccess.Unlock()
	err := c.saveFakeIPMetadata(metadata)
	if err == nil {
		c.saveMetadata = nil
	} else {
		c.saveMetadata = metadata
		c.saveMetadataDue = time.Now()
		c.wakeCacheWriter()
	}
	return err
}

func (c *CacheFile) saveFakeIPMetadata(metadata *adapter.FakeIPMetadata) error {
	return c.update(func(tx *bbolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists(bucketFakeIP)
		if err != nil {
			return err
		}
		metadataBinary, err := metadata.MarshalBinary()
		if err != nil {
			return err
		}
		return bucket.Put(keyMetadata, metadataBinary)
	})
}

func (c *CacheFile) FakeIPSaveMetadataAsync(metadata *adapter.FakeIPMetadata) {
	c.saveMetadataAccess.Lock()
	defer c.saveMetadataAccess.Unlock()
	c.saveMetadata = metadata
	c.saveMetadataDue = time.Now().Add(C.FakeIPMetadataSaveInterval)
	c.wakeCacheWriter()
}

func (c *CacheFile) FakeIPStore(address netip.Addr, domain string) error {
	c.cacheWriteAccess.Lock()
	defer c.cacheWriteAccess.Unlock()
	c.saveFakeIPAccess.Lock()
	defer c.saveFakeIPAccess.Unlock()
	err := c.writeFakeIP(address, domain)
	if err == nil {
		addresses := c.saveAddress4
		if address.Is6() {
			addresses = c.saveAddress6
		}
		if oldDomain, loaded := c.saveDomain[address]; loaded {
			if addresses[oldDomain] == address {
				delete(addresses, oldDomain)
			}
			delete(c.saveDomain, address)
		}
		if oldAddress, loaded := addresses[domain]; loaded {
			if c.saveDomain[oldAddress] == domain {
				delete(c.saveDomain, oldAddress)
			}
			delete(addresses, domain)
		}
	} else {
		c.queueFakeIPLocked(address, domain)
		c.wakeCacheWriter()
	}
	return err
}

func (c *CacheFile) writeFakeIP(address netip.Addr, domain string) error {
	return c.update(func(tx *bbolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists(bucketFakeIP)
		if err != nil {
			return err
		}
		oldDomain := string(bucket.Get(address.AsSlice()))
		err = bucket.Put(address.AsSlice(), []byte(domain))
		if err != nil {
			return err
		}
		if address.Is4() {
			bucket, err = tx.CreateBucketIfNotExists(bucketFakeIPDomain4)
		} else {
			bucket, err = tx.CreateBucketIfNotExists(bucketFakeIPDomain6)
		}
		if err != nil {
			return err
		}
		if oldDomain != "" && bytes.Equal(bucket.Get([]byte(oldDomain)), address.AsSlice()) {
			if err := bucket.Delete([]byte(oldDomain)); err != nil {
				return err
			}
		}
		if previous := bucket.Get([]byte(domain)); previous != nil && !bytes.Equal(previous, address.AsSlice()) {
			forward := tx.Bucket(bucketFakeIP)
			if string(forward.Get(previous)) == domain {
				if err := forward.Delete(previous); err != nil {
					return err
				}
			}
		}
		return bucket.Put([]byte(domain), address.AsSlice())
	})
}

func (c *CacheFile) FakeIPStoreAsync(address netip.Addr, domain string, logger logger.Logger) {
	c.saveFakeIPAccess.Lock()
	c.queueFakeIPLocked(address, domain)
	c.saveFakeIPAccess.Unlock()
	c.wakeCacheWriter()
}

func (c *CacheFile) queueFakeIPLocked(address netip.Addr, domain string) {
	addresses := c.saveAddress4
	if address.Is6() {
		addresses = c.saveAddress6
	}
	if oldAddress, loaded := addresses[domain]; loaded && oldAddress != address && c.saveDomain[oldAddress] == domain {
		delete(c.saveDomain, oldAddress)
	}
	if oldDomain, loaded := c.saveDomain[address]; loaded {
		if address.Is4() {
			delete(c.saveAddress4, oldDomain)
		} else {
			delete(c.saveAddress6, oldDomain)
		}
	}
	c.saveDomain[address] = domain
	if address.Is4() {
		c.saveAddress4[domain] = address
	} else {
		c.saveAddress6[domain] = address
	}
}

func (c *CacheFile) FakeIPLoad(address netip.Addr) (string, bool) {
	c.saveFakeIPAccess.RLock()
	cachedDomain, cached := c.saveDomain[address]
	c.saveFakeIPAccess.RUnlock()
	if cached {
		return cachedDomain, true
	}
	var domain string
	_ = c.view(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(bucketFakeIP)
		if bucket == nil {
			return nil
		}
		domain = string(bucket.Get(address.AsSlice()))
		return nil
	})
	return domain, domain != ""
}

func (c *CacheFile) FakeIPLoadDomain(domain string, isIPv6 bool) (netip.Addr, bool) {
	var (
		cachedAddress netip.Addr
		cached        bool
	)
	c.saveFakeIPAccess.RLock()
	if !isIPv6 {
		cachedAddress, cached = c.saveAddress4[domain]
	} else {
		cachedAddress, cached = c.saveAddress6[domain]
	}
	c.saveFakeIPAccess.RUnlock()
	if cached {
		return cachedAddress, true
	}
	var address netip.Addr
	_ = c.view(func(tx *bbolt.Tx) error {
		var bucket *bbolt.Bucket
		if isIPv6 {
			bucket = tx.Bucket(bucketFakeIPDomain6)
		} else {
			bucket = tx.Bucket(bucketFakeIPDomain4)
		}
		if bucket == nil {
			return nil
		}
		address = M.AddrFromIP(bucket.Get([]byte(domain)))
		return nil
	})
	return address, address.IsValid()
}

func (c *CacheFile) FakeIPReset() error {
	c.cacheWriteAccess.Lock()
	defer c.cacheWriteAccess.Unlock()
	c.saveFakeIPAccess.Lock()
	clear(c.saveDomain)
	clear(c.saveAddress4)
	clear(c.saveAddress6)
	c.saveFakeIPAccess.Unlock()
	c.saveMetadataAccess.Lock()
	c.saveMetadata = nil
	c.saveMetadataAccess.Unlock()
	return c.batch(func(tx *bbolt.Tx) error {
		for _, bucketName := range [][]byte{bucketFakeIP, bucketFakeIPDomain4, bucketFakeIPDomain6} {
			if tx.Bucket(bucketName) == nil {
				continue
			}
			err := tx.DeleteBucket(bucketName)
			if err != nil {
				return err
			}
		}
		return nil
	})
}
