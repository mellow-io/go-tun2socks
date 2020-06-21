package cache

import (
	"net"
	"sync"
	"time"

	cdns "github.com/eycorsican/go-tun2socks/common/dns"
	"github.com/eycorsican/go-tun2socks/common/log"
)

type ipCacheEntry struct {
	ips []net.IP
	exp time.Time
}

type simpleIPCache struct {
	mutex       sync.Mutex
	storage     map[string]*ipCacheEntry
	lastCleanup time.Time
}

func NewSimpleIPCache() cdns.IPCache {
	return &simpleIPCache{
		storage:     make(map[string]*ipCacheEntry),
		lastCleanup: time.Now(),
	}
}

func (c *simpleIPCache) cleanup() {
	newStorage := make(map[string]*ipCacheEntry)
	log.Debugf("cleaning up dns %v cache entries", len(c.storage))
	for key, entry := range c.storage {
		if time.Now().Before(entry.exp) {
			newStorage[key] = entry
		}
	}
	c.storage = newStorage
	log.Debugf("cleanup done, remaining %v entries", len(c.storage))
}

func (c *simpleIPCache) Query(domain string) []net.IP {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	entry := c.storage[domain]
	if entry == nil {
		return nil
	}
	if time.Now().After(entry.exp) {
		delete(c.storage, domain)
		return nil
	}

	log.Debugf("returning %v ips for %v", len(entry.ips), domain)
	return entry.ips
}

func (c *simpleIPCache) Store(domain string, ips []net.IP, ttl uint32) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.storage[domain] = &ipCacheEntry{
		ips: ips,
		exp: time.Now().Add(time.Duration(ttl) * time.Second),
	}
	log.Debugf("cache %v ips for %v, ttl: %v", len(ips), domain, ttl)

	now := time.Now()
	if now.Sub(c.lastCleanup) > minCleanupInterval {
		c.cleanup()
		c.lastCleanup = now
	}
}
