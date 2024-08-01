package main

import (
	"container/list"
	"github.com/miekg/dns"
	"sync"
	"time"
)

/**
 * @Author: gedebin
 * @Date: 2024/8/1 10:24
 * @Desc:
 */

var cacheMap = make(map[string]*Cache)

// CacheEntry represents a single DNS cache entry
type CacheEntry struct {
	Msg       *dns.Msg
	ExpiresAt time.Time
}

// Cache represents a DNS cache with LRU eviction policy
type Cache struct {
	mu      sync.RWMutex
	entries map[string]*list.Element
	lru     *list.List
	timers  map[string]*time.Timer
}

// entry represents a single element in Cache lru list
type entry struct {
	key   string
	value CacheEntry
}

const (
	// MaxCacheEntries is the maximum number of cache entries per source IP
	MaxCacheEntries = 1000
	// SOCKS5 DNS header + at least one RR
	minDNSResponseLength = 12
)

// minTTL calculates the minimum TTL from a DNS message
func minTTL(msg *dns.Msg) uint32 {
	minTTL := ^uint32(0)
	for _, ans := range msg.Answer {
		if ans.Header().Ttl < minTTL {
			minTTL = ans.Header().Ttl
		}
	}
	return minTTL
}

// scheduleExpiration schedules the expiration of a cache entry
func (c *Cache) scheduleExpiration(e *entry) *time.Timer {
	return time.AfterFunc(time.Until(e.value.ExpiresAt), func() {
		c.mu.Lock()
		defer c.mu.Unlock()

		if el, found := c.entries[e.key]; found && el.Value.(*entry).value.ExpiresAt == e.value.ExpiresAt {
			c.removeElement(el)
		}
	})
}

// removeElement removes an element from the cache
func (c *Cache) removeElement(el *list.Element) {
	key := el.Value.(*entry).key
	c.lru.Remove(el)
	delete(c.entries, key)
	if timer, exists := c.timers[key]; exists {
		timer.Stop()
		delete(c.timers, key)
	}
}

// NewCache creates a new Cache
func NewCache() *Cache {
	return &Cache{
		entries: make(map[string]*list.Element),
		lru:     list.New(),
		timers:  make(map[string]*time.Timer),
	}
}

// Get retrieves a DNS response from the cache
func (c *Cache) Get(key string) (*dns.Msg, bool) {
	c.mu.RLock()
	el, found := c.entries[key]
	if found && time.Now().Before(el.Value.(*entry).value.ExpiresAt) {
		c.lru.MoveToFront(el)
		msg := el.Value.(*entry).value.Msg
		c.mu.RUnlock()
		return msg, true
	}
	c.mu.RUnlock()

	if found {
		c.mu.Lock()
		// Re-check if the element is still present and expired, then remove it
		if el, stillFound := c.entries[key]; stillFound && time.Now().After(el.Value.(*entry).value.ExpiresAt) {
			c.removeElement(el)
		}
		c.mu.Unlock()
	}
	return nil, false
}

// Put adds a DNS response to the cache
func (c *Cache) Put(key string, msg *dns.Msg) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if el, found := c.entries[key]; found {
		c.lru.MoveToFront(el)
		el.Value.(*entry).value = CacheEntry{
			Msg:       msg,
			ExpiresAt: time.Now().Add(time.Duration(minTTL(msg)) * time.Second),
		}
		if timer, exists := c.timers[key]; exists {
			timer.Stop()
			delete(c.timers, key)
		}
		c.timers[key] = c.scheduleExpiration(el.Value.(*entry))
	} else {
		if c.lru.Len() >= MaxCacheEntries {
			el := c.lru.Back()
			if el != nil {
				c.removeElement(el)
			}
		}
		newEntry := &entry{
			key: key,
			value: CacheEntry{
				Msg:       msg,
				ExpiresAt: time.Now().Add(time.Duration(minTTL(msg)) * time.Second),
			},
		}
		c.entries[key] = c.lru.PushFront(newEntry)
		c.timers[key] = c.scheduleExpiration(newEntry)
	}
}
