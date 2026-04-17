package cachefile

import (
	"maps"
	"time"

	"github.com/sagernet/sing/common/logger"
)

const cacheRetryInterval = time.Second

// Keep the existing per-cache buffers. One worker serializes their asynchronous
// writes and retries failed entries without creating a goroutine per retry.
func (c *CacheFile) wakeCacheWriter() {
	c.writerAccess.Lock()
	defer c.writerAccess.Unlock()
	if c.writerClosed {
		return
	}
	if c.writerWake == nil {
		c.writerWake = make(chan struct{}, 1)
		c.writerStop = make(chan struct{})
		c.writerDone = make(chan struct{})
		go c.loopCacheWriter()
	}
	select {
	case c.writerWake <- struct{}{}:
	default:
	}
}

func (c *CacheFile) stopCacheWriter() {
	c.writerAccess.Lock()
	if !c.writerClosed {
		c.writerClosed = true
		if c.writerStop != nil {
			close(c.writerStop)
		}
	}
	done := c.writerDone
	c.writerAccess.Unlock()
	if done != nil {
		<-done
	}
}

func (c *CacheFile) loopCacheWriter() {
	defer close(c.writerDone)
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	defer timer.Stop()
	var retry <-chan time.Time
	var canceled <-chan struct{}
	if c.ctx != nil {
		canceled = c.ctx.Done()
	}
	for {
		select {
		case <-c.writerStop:
			c.flushCacheWrites(true)
			return
		case <-canceled:
			c.flushCacheWrites(true)
			return
		case <-c.writerWake:
		case <-retry:
		}
		delay := c.flushCacheWrites(false)
		timer.Stop()
		retry = nil
		if delay > 0 {
			timer.Reset(delay)
			retry = timer.C
		}
	}
}

func (c *CacheFile) flushCacheWrites(final bool) time.Duration {
	c.cacheWriteAccess.Lock()
	defer c.cacheWriteAccess.Unlock()
	log := c.logger
	if log == nil {
		log = logger.NOP()
	}
	var delay time.Duration
	failed := func(err error) {
		if err != nil {
			log.Warn("save cache: ", err)
			delay = cacheRetryInterval
		}
	}
	c.saveDNSCacheAccess.RLock()
	dnsEntries := maps.Clone(c.saveDNSCache)
	c.saveDNSCacheAccess.RUnlock()
	for key := range dnsEntries {
		c.flushPendingDNSCache(key, log)
	}
	c.saveDNSCacheAccess.RLock()
	if len(c.saveDNSCache) > 0 {
		delay = cacheRetryInterval
	}
	c.saveDNSCacheAccess.RUnlock()

	c.saveRDRCAccess.RLock()
	rdrcEntries := maps.Clone(c.saveRDRC)
	c.saveRDRCAccess.RUnlock()
	for key, expireAt := range rdrcEntries {
		var err error
		if time.Now().Before(expireAt) {
			err = c.saveRDRCUntil(key.TransportName, key.QuestionName, key.QType, expireAt)
		}
		failed(err)
		if err == nil {
			c.saveRDRCAccess.Lock()
			if c.saveRDRC[key].Equal(expireAt) {
				delete(c.saveRDRC, key)
			}
			c.saveRDRCAccess.Unlock()
		}
	}

	c.saveFakeIPAccess.RLock()
	fakeIPEntries := maps.Clone(c.saveDomain)
	c.saveFakeIPAccess.RUnlock()
	for address, domain := range fakeIPEntries {
		c.saveFakeIPAccess.RLock()
		current, exists := c.saveDomain[address]
		c.saveFakeIPAccess.RUnlock()
		if !exists || current != domain {
			continue
		}
		err := c.writeFakeIP(address, domain)
		failed(err)
		if err == nil {
			c.saveFakeIPAccess.Lock()
			if c.saveDomain[address] == domain {
				delete(c.saveDomain, address)
			}
			if address.Is4() {
				if c.saveAddress4[domain] == address {
					delete(c.saveAddress4, domain)
				}
			} else {
				if c.saveAddress6[domain] == address {
					delete(c.saveAddress6, domain)
				}
			}
			c.saveFakeIPAccess.Unlock()
		}
	}

	c.saveMetadataAccess.Lock()
	metadata, due := c.saveMetadata, c.saveMetadataDue
	c.saveMetadataAccess.Unlock()
	if metadata != nil {
		if final || !time.Now().Before(due) {
			err := c.saveFakeIPMetadata(metadata)
			failed(err)
			if err == nil {
				c.saveMetadataAccess.Lock()
				if c.saveMetadata == metadata && c.saveMetadataDue.Equal(due) {
					c.saveMetadata = nil
				}
				c.saveMetadataAccess.Unlock()
			}
		} else if remaining := time.Until(due); delay == 0 || remaining < delay {
			delay = max(remaining, time.Nanosecond)
		}
	}
	return delay
}
