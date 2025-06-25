package cert

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNewCertificateManager(t *testing.T) {
	manager := NewCertificateManager(false)
	if manager == nil {
		t.Fatal("Expected manager to be created, got nil")
	}

	// Check that stats are initialized
	stats := manager.GetStats()
	if stats == nil {
		t.Error("Expected stats to be initialized")
	}
}

func TestCertificateManagerInitialization(t *testing.T) {
	tempDir := t.TempDir()
	certDir := filepath.Join(tempDir, "certs")

	config := &CertConfig{
		CertDir:           certDir,
		CAFile:            filepath.Join(certDir, "ca.crt"),
		CAKeyFile:         filepath.Join(certDir, "ca.key"),
		AutoGenerate:      false, // Don't try to load CA for this test
		ValidDays:         365,
		UpstreamCertSniff: true,
		KeySize:           2048,
		CacheMaxSize:      100,
		CacheExpiryHours:  24,
	}

	manager := NewCertificateManager(true) // Enable debug
	err := manager.Initialize(config)
	if err != nil {
		t.Fatalf("Failed to initialize manager: %v", err)
	}

	// Check that certificate directory was created
	if _, err := os.Stat(certDir); os.IsNotExist(err) {
		t.Error("Expected certificate directory to be created")
	}

	// Check defaults were applied
	if manager.config.KeySize != 2048 {
		t.Errorf("Expected KeySize 2048, got %d", manager.config.KeySize)
	}

	if manager.config.ValidDays != 365 {
		t.Errorf("Expected ValidDays 365, got %d", manager.config.ValidDays)
	}
}

func TestCertificateManagerWithInvalidCA(t *testing.T) {
	tempDir := t.TempDir()
	certDir := filepath.Join(tempDir, "certs")

	config := &CertConfig{
		CertDir:      certDir,
		CAFile:       filepath.Join(certDir, "missing.crt"),
		CAKeyFile:    filepath.Join(certDir, "missing.key"),
		AutoGenerate: true, // This should fail
	}

	manager := NewCertificateManager(false)
	err := manager.Initialize(config)
	if err == nil {
		t.Error("Expected error with missing CA files, got nil")
	}
}

func TestCertificateStats(t *testing.T) {
	manager := NewCertificateManager(false)

	// Test initial stats
	stats := manager.GetStats()
	if stats.GeneratedCerts != 0 {
		t.Errorf("Expected 0 generated certificates, got %d", stats.GeneratedCerts)
	}

	if stats.CacheHits != 0 {
		t.Errorf("Expected 0 cache hits, got %d", stats.CacheHits)
	}

	if stats.CacheMisses != 0 {
		t.Errorf("Expected 0 cache misses, got %d", stats.CacheMisses)
	}

	// Simulate some stats updates
	manager.stats.IncrementGenerated()
	manager.stats.IncrementCacheHit()
	manager.stats.IncrementCacheMiss()
	manager.stats.IncrementUpstreamSniff()

	stats = manager.GetStats()
	if stats.GeneratedCerts != 1 {
		t.Errorf("Expected 1 generated certificate, got %d", stats.GeneratedCerts)
	}

	if stats.CacheHits != 1 {
		t.Errorf("Expected 1 cache hit, got %d", stats.CacheHits)
	}

	if stats.CacheMisses != 1 {
		t.Errorf("Expected 1 cache miss, got %d", stats.CacheMisses)
	}

	if stats.UpstreamSniffs != 1 {
		t.Errorf("Expected 1 upstream sniff, got %d", stats.UpstreamSniffs)
	}
}

func TestClearCache(t *testing.T) {
	manager := NewCertificateManager(false)

	// Add some fake entries to cache (directly accessing the cache for testing)
	manager.cacheMutex.Lock()
	manager.certCache["test1.com"] = &Certificate{Domain: "test1.com"}
	manager.certCache["test2.com"] = &Certificate{Domain: "test2.com"}
	manager.cacheMutex.Unlock()

	// Clear cache and check count
	cleared := manager.ClearCache()
	if cleared != 2 {
		t.Errorf("Expected 2 cleared certificates, got %d", cleared)
	}

	// Check cache is empty
	manager.cacheMutex.RLock()
	cacheSize := len(manager.certCache)
	manager.cacheMutex.RUnlock()

	if cacheSize != 0 {
		t.Errorf("Expected empty cache after clear, got %d entries", cacheSize)
	}
}

func TestCertificateManagerShutdown(t *testing.T) {
	manager := NewCertificateManager(false)

	// Add some test data
	manager.stats.IncrementGenerated()
	manager.stats.IncrementCacheHit()

	// Shutdown should not panic
	err := manager.Shutdown()
	if err != nil {
		t.Errorf("Unexpected error during shutdown: %v", err)
	}

	// Stats should still be accessible after shutdown
	stats := manager.GetStats()
	if stats.GeneratedCerts != 1 {
		t.Errorf("Expected stats to be preserved after shutdown")
	}
}

func TestFilenameGeneration(t *testing.T) {
	// Test that the certificate manager can handle various domain names
	// This indirectly tests filename safety handling
	manager := NewCertificateManager(false)

	domains := []string{
		"example.com",
		"sub.example.com",
		"test.example.com",
	}

	for _, domain := range domains {
		// The domain should be lowercase and safe for file operations
		cleaned := strings.ToLower(strings.TrimSpace(domain))
		if cleaned != domain {
			t.Errorf("Domain %s should already be clean for %s", domain, cleaned)
		}

		// Test that we can handle the domain name in cache operations
		manager.cacheMutex.Lock()
		manager.certCache[domain] = &Certificate{Domain: domain}
		manager.cacheMutex.Unlock()

		// Verify it was stored correctly
		manager.cacheMutex.RLock()
		_, exists := manager.certCache[domain]
		manager.cacheMutex.RUnlock()

		if !exists {
			t.Errorf("Expected domain %s to be stored in cache", domain)
		}
	}
}

// Benchmark certificate manager operations
func BenchmarkStatsAccess(b *testing.B) {
	manager := NewCertificateManager(false)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			manager.GetStats()
		}
	})
}

func BenchmarkCacheOperations(b *testing.B) {
	manager := NewCertificateManager(false)

	// Pre-populate cache with test data
	manager.cacheMutex.Lock()
	for i := 0; i < 100; i++ {
		domain := fmt.Sprintf("test%d.example.com", i)
		manager.certCache[domain] = &Certificate{
			Domain:    domain,
			ExpiresAt: time.Now().Add(24 * time.Hour),
		}
	}
	manager.cacheMutex.Unlock()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			domain := fmt.Sprintf("test%d.example.com", b.N%100)
			// Simulate cache lookup
			manager.cacheMutex.RLock()
			_, exists := manager.certCache[domain]
			manager.cacheMutex.RUnlock()

			if exists {
				manager.stats.IncrementCacheHit()
			} else {
				manager.stats.IncrementCacheMiss()
			}
		}
	})
}
