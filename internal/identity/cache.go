package identity

import (
	"sync"
	"time"
)

// MemoryCache implements IdentityCache using in-memory storage
type MemoryCache struct {
	data     map[string]*cacheEntry
	mutex    sync.RWMutex
	maxSize  int
	stats    CacheStats
	statsMux sync.RWMutex
}

// cacheEntry represents a cached identity with expiration
type cacheEntry struct {
	identity  *IdentityContext
	expiresAt time.Time
}

// NewMemoryCache creates a new in-memory identity cache
func NewMemoryCache(maxSize int) IdentityCache {
	if maxSize <= 0 {
		maxSize = 10000 // Default max size
	}

	cache := &MemoryCache{
		data:    make(map[string]*cacheEntry),
		maxSize: maxSize,
		stats:   CacheStats{},
	}

	// Start cleanup goroutine
	go cache.cleanupExpired()

	return cache
}

// Get retrieves an identity from cache
func (mc *MemoryCache) Get(key string) (*IdentityContext, bool) {
	mc.mutex.RLock()
	entry, exists := mc.data[key]
	mc.mutex.RUnlock()

	if !exists {
		mc.updateStats(false, false)
		return nil, false
	}

	// Check expiration
	if time.Now().After(entry.expiresAt) {
		mc.mutex.Lock()
		delete(mc.data, key)
		mc.mutex.Unlock()
		mc.updateStats(false, false)
		return nil, false
	}

	mc.updateStats(true, false)
	return entry.identity, true
}

// Set stores an identity in cache with TTL
func (mc *MemoryCache) Set(key string, identity *IdentityContext, ttl time.Duration) {
	mc.mutex.Lock()
	defer mc.mutex.Unlock()

	// Check if we need to evict entries
	if len(mc.data) >= mc.maxSize {
		mc.evictOldest()
	}

	// Store the entry
	mc.data[key] = &cacheEntry{
		identity:  identity,
		expiresAt: time.Now().Add(ttl),
	}
}

// Delete removes an identity from cache
func (mc *MemoryCache) Delete(key string) {
	mc.mutex.Lock()
	defer mc.mutex.Unlock()
	delete(mc.data, key)
}

// Clear removes all entries from cache
func (mc *MemoryCache) Clear() {
	mc.mutex.Lock()
	defer mc.mutex.Unlock()
	mc.data = make(map[string]*cacheEntry)
}

// Size returns the current number of cached entries
func (mc *MemoryCache) Size() int {
	mc.mutex.RLock()
	defer mc.mutex.RUnlock()
	return len(mc.data)
}

// Stats returns cache performance statistics
func (mc *MemoryCache) Stats() CacheStats {
	mc.statsMux.RLock()
	defer mc.statsMux.RUnlock()

	stats := mc.stats
	stats.Size = mc.Size()

	// Calculate hit ratio
	total := stats.Hits + stats.Misses
	if total > 0 {
		stats.HitRatio = float64(stats.Hits) / float64(total)
	}

	return stats
}

// evictOldest removes the oldest entry from cache (simple FIFO eviction)
func (mc *MemoryCache) evictOldest() {
	if len(mc.data) == 0 {
		return
	}

	var oldestKey string
	var oldestTime time.Time

	for key, entry := range mc.data {
		if oldestKey == "" || entry.expiresAt.Before(oldestTime) {
			oldestKey = key
			oldestTime = entry.expiresAt
		}
	}

	if oldestKey != "" {
		delete(mc.data, oldestKey)
		mc.updateStats(false, true)
	}
}

// cleanupExpired periodically removes expired entries
func (mc *MemoryCache) cleanupExpired() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		mc.mutex.Lock()
		now := time.Now()
		keysToDelete := make([]string, 0)

		for key, entry := range mc.data {
			if now.After(entry.expiresAt) {
				keysToDelete = append(keysToDelete, key)
			}
		}

		for _, key := range keysToDelete {
			delete(mc.data, key)
		}

		mc.mutex.Unlock()

		if len(keysToDelete) > 0 {
			mc.updateStats(false, true)
		}
	}
}

// updateStats updates cache performance statistics
func (mc *MemoryCache) updateStats(hit bool, eviction bool) {
	mc.statsMux.Lock()
	defer mc.statsMux.Unlock()

	if hit {
		mc.stats.Hits++
	} else {
		mc.stats.Misses++
	}

	if eviction {
		mc.stats.Evictions++
	}
}
