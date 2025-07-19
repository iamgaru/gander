package tls

import (
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"sync"
	"time"
)

// SessionCache provides TLS session resumption capabilities
type SessionCache struct {
	sessions        map[string]*SessionEntry
	sessionsMutex   sync.RWMutex
	ticketKeys      [][32]byte
	ticketKeysMutex sync.RWMutex
	maxSessions     int
	sessionTTL      time.Duration
	enableDebug     bool
	stats           *SessionCacheStats
}

// SessionEntry represents a cached TLS session
type SessionEntry struct {
	SessionID    []byte
	SessionState *tls.ClientSessionState
	CreatedAt    time.Time
	LastUsed     time.Time
	UseCount     int
	ClientAddr   string
	ServerName   string
}

// SessionCacheStats tracks session cache performance
type SessionCacheStats struct {
	mutex              sync.RWMutex
	TotalSessions      int64
	ActiveSessions     int64
	SessionHits        int64
	SessionMisses      int64
	SessionsCreated    int64
	SessionsExpired    int64
	TicketKeyRotations int64
	ResumptionRate     float64
	AverageSessionLife time.Duration
}

// SessionCacheStatsSnapshot represents a snapshot of session cache statistics without mutex
type SessionCacheStatsSnapshot struct {
	TotalSessions      int64
	ActiveSessions     int64
	SessionHits        int64
	SessionMisses      int64
	SessionsCreated    int64
	SessionsExpired    int64
	TicketKeyRotations int64
	ResumptionRate     float64
	AverageSessionLife time.Duration
}

// SessionCacheConfig contains configuration for the session cache
type SessionCacheConfig struct {
	MaxSessions       int
	SessionTTL        time.Duration
	TicketKeyRotation time.Duration
	CleanupInterval   time.Duration
	EnableDebug       bool
	EnableClientCache bool
	EnableServerCache bool
}

// NewSessionCache creates a new TLS session cache
func NewSessionCache(config *SessionCacheConfig) *SessionCache {
	if config.MaxSessions == 0 {
		config.MaxSessions = 10000
	}
	if config.SessionTTL == 0 {
		config.SessionTTL = 24 * time.Hour
	}
	if config.TicketKeyRotation == 0 {
		config.TicketKeyRotation = 1 * time.Hour
	}
	if config.CleanupInterval == 0 {
		config.CleanupInterval = 5 * time.Minute
	}

	cache := &SessionCache{
		sessions:    make(map[string]*SessionEntry),
		maxSessions: config.MaxSessions,
		sessionTTL:  config.SessionTTL,
		enableDebug: config.EnableDebug,
		stats:       &SessionCacheStats{},
	}

	// Initialize ticket keys
	cache.rotateTicketKeys()

	// Start background workers
	go cache.cleanupWorker(config.CleanupInterval)
	go cache.ticketKeyRotationWorker(config.TicketKeyRotation)

	return cache
}

// Get retrieves a session from the cache (implements tls.ClientSessionCache)
func (sc *SessionCache) Get(sessionKey string) (*tls.ClientSessionState, bool) {
	sc.sessionsMutex.RLock()
	entry, exists := sc.sessions[sessionKey]
	sc.sessionsMutex.RUnlock()

	if !exists {
		sc.stats.recordMiss()
		return nil, false
	}

	// Check if session has expired
	if time.Since(entry.CreatedAt) > sc.sessionTTL {
		sc.removeSession(sessionKey)
		sc.stats.recordMiss()
		sc.stats.recordExpired()
		return nil, false
	}

	// Update last used time and use count
	sc.sessionsMutex.Lock()
	entry.LastUsed = time.Now()
	entry.UseCount++
	sc.sessionsMutex.Unlock()

	sc.stats.recordHit()

	if sc.enableDebug {
		fmt.Printf("TLS session cache hit for %s (use count: %d)\n", sessionKey, entry.UseCount)
	}

	return entry.SessionState, true
}

// Put stores a session in the cache (implements tls.ClientSessionCache)
func (sc *SessionCache) Put(sessionKey string, sessionState *tls.ClientSessionState) {
	if sessionState == nil {
		return
	}

	// Check if we've reached max capacity
	if len(sc.sessions) >= sc.maxSessions {
		sc.evictOldestSession()
	}

	entry := &SessionEntry{
		SessionState: sessionState,
		CreatedAt:    time.Now(),
		LastUsed:     time.Now(),
		UseCount:     0,
	}

	sc.sessionsMutex.Lock()
	sc.sessions[sessionKey] = entry
	sc.sessionsMutex.Unlock()

	sc.stats.recordCreated()

	if sc.enableDebug {
		fmt.Printf("TLS session cached for %s\n", sessionKey)
	}
}

// PutWithContext stores a session with additional context information
func (sc *SessionCache) PutWithContext(sessionKey string, sessionState *tls.ClientSessionState, clientAddr, serverName string) {
	if sessionState == nil {
		return
	}

	// Check if we've reached max capacity
	if len(sc.sessions) >= sc.maxSessions {
		sc.evictOldestSession()
	}

	entry := &SessionEntry{
		SessionState: sessionState,
		CreatedAt:    time.Now(),
		LastUsed:     time.Now(),
		UseCount:     0,
		ClientAddr:   clientAddr,
		ServerName:   serverName,
	}

	// Note: SessionTicket field was removed from SessionState in newer Go versions
	// We'll generate a simple session ID based on the server name and timestamp
	if serverName != "" {
		entry.SessionID = []byte(fmt.Sprintf("%s-%d", serverName, time.Now().UnixNano()))
	}

	sc.sessionsMutex.Lock()
	sc.sessions[sessionKey] = entry
	sc.sessionsMutex.Unlock()

	sc.stats.recordCreated()

	if sc.enableDebug {
		fmt.Printf("TLS session cached for %s (client: %s, server: %s)\n",
			sessionKey, clientAddr, serverName)
	}
}

// removeSession removes a session from the cache
func (sc *SessionCache) removeSession(sessionKey string) {
	sc.sessionsMutex.Lock()
	delete(sc.sessions, sessionKey)
	sc.sessionsMutex.Unlock()
}

// evictOldestSession removes the oldest session to make room for new ones
func (sc *SessionCache) evictOldestSession() {
	sc.sessionsMutex.Lock()
	defer sc.sessionsMutex.Unlock()

	var oldestKey string
	var oldestTime time.Time

	for key, entry := range sc.sessions {
		if oldestKey == "" || entry.CreatedAt.Before(oldestTime) {
			oldestKey = key
			oldestTime = entry.CreatedAt
		}
	}

	if oldestKey != "" {
		delete(sc.sessions, oldestKey)
		if sc.enableDebug {
			fmt.Printf("Evicted oldest TLS session: %s\n", oldestKey)
		}
	}
}

// cleanupWorker periodically removes expired sessions
func (sc *SessionCache) cleanupWorker(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		sc.cleanup()
	}
}

// cleanup removes expired sessions
func (sc *SessionCache) cleanup() {
	now := time.Now()
	var expiredKeys []string

	sc.sessionsMutex.RLock()
	for key, entry := range sc.sessions {
		if now.Sub(entry.CreatedAt) > sc.sessionTTL {
			expiredKeys = append(expiredKeys, key)
		}
	}
	sc.sessionsMutex.RUnlock()

	if len(expiredKeys) > 0 {
		sc.sessionsMutex.Lock()
		for _, key := range expiredKeys {
			delete(sc.sessions, key)
		}
		sc.sessionsMutex.Unlock()

		sc.stats.mutex.Lock()
		sc.stats.SessionsExpired += int64(len(expiredKeys))
		sc.stats.mutex.Unlock()

		if sc.enableDebug {
			fmt.Printf("Cleaned up %d expired TLS sessions\n", len(expiredKeys))
		}
	}
}

// GetTicketKeys returns current ticket keys for TLS session tickets
func (sc *SessionCache) GetTicketKeys() [][32]byte {
	sc.ticketKeysMutex.RLock()
	defer sc.ticketKeysMutex.RUnlock()

	// Return a copy to prevent external modification
	keys := make([][32]byte, len(sc.ticketKeys))
	copy(keys, sc.ticketKeys)
	return keys
}

// rotateTicketKeys generates new ticket keys
func (sc *SessionCache) rotateTicketKeys() {
	// Generate 3 ticket keys (current, previous, and next)
	newKeys := make([][32]byte, 3)
	for i := range newKeys {
		if _, err := rand.Read(newKeys[i][:]); err != nil {
			if sc.enableDebug {
				fmt.Printf("Failed to generate ticket key: %v\n", err)
			}
			return
		}
	}

	sc.ticketKeysMutex.Lock()
	sc.ticketKeys = newKeys
	sc.ticketKeysMutex.Unlock()

	sc.stats.recordTicketKeyRotation()

	if sc.enableDebug {
		fmt.Printf("TLS ticket keys rotated\n")
	}
}

// ticketKeyRotationWorker periodically rotates ticket keys
func (sc *SessionCache) ticketKeyRotationWorker(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		sc.rotateTicketKeys()
	}
}

// GetStats returns current session cache statistics
func (sc *SessionCache) GetStats() SessionCacheStatsSnapshot {
	sc.stats.mutex.RLock()
	defer sc.stats.mutex.RUnlock()

	sc.sessionsMutex.RLock()
	activeSessions := int64(len(sc.sessions))
	sc.sessionsMutex.RUnlock()

	// Create a snapshot without copying the mutex
	stats := SessionCacheStatsSnapshot{
		TotalSessions:      sc.stats.TotalSessions,
		ActiveSessions:     activeSessions,
		SessionHits:        sc.stats.SessionHits,
		SessionMisses:      sc.stats.SessionMisses,
		SessionsCreated:    sc.stats.SessionsCreated,
		SessionsExpired:    sc.stats.SessionsExpired,
		TicketKeyRotations: sc.stats.TicketKeyRotations,
		AverageSessionLife: sc.stats.AverageSessionLife,
	}

	// Calculate resumption rate
	totalAttempts := stats.SessionHits + stats.SessionMisses
	if totalAttempts > 0 {
		stats.ResumptionRate = float64(stats.SessionHits) / float64(totalAttempts)
	}

	return stats
}

// GetSessionDetails returns detailed information about cached sessions
func (sc *SessionCache) GetSessionDetails() []SessionEntry {
	sc.sessionsMutex.RLock()
	defer sc.sessionsMutex.RUnlock()

	details := make([]SessionEntry, 0, len(sc.sessions))
	for _, entry := range sc.sessions {
		// Create a copy to avoid data races
		details = append(details, *entry)
	}

	return details
}

// Clear removes all sessions from the cache
func (sc *SessionCache) Clear() int {
	sc.sessionsMutex.Lock()
	count := len(sc.sessions)
	sc.sessions = make(map[string]*SessionEntry)
	sc.sessionsMutex.Unlock()

	if sc.enableDebug && count > 0 {
		fmt.Printf("Cleared %d TLS sessions from cache\n", count)
	}

	return count
}

// SetTicketKeys manually sets the ticket keys (for testing or external management)
func (sc *SessionCache) SetTicketKeys(keys [][32]byte) {
	sc.ticketKeysMutex.Lock()
	sc.ticketKeys = make([][32]byte, len(keys))
	copy(sc.ticketKeys, keys)
	sc.ticketKeysMutex.Unlock()

	if sc.enableDebug {
		fmt.Printf("TLS ticket keys manually set (%d keys)\n", len(keys))
	}
}

// CreateTLSConfig creates a TLS config with session resumption enabled
func (sc *SessionCache) CreateTLSConfig(baseCfg *tls.Config) *tls.Config {
	cfg := baseCfg.Clone()

	// Set session cache
	cfg.ClientSessionCache = sc

	// Set ticket keys
	ticketKeys := sc.GetTicketKeys()
	if len(ticketKeys) > 0 {
		cfg.SetSessionTicketKeys(ticketKeys)
	}

	// Enable session tickets
	cfg.SessionTicketsDisabled = false

	return cfg
}

// Statistics recording methods

func (scs *SessionCacheStats) recordHit() {
	scs.mutex.Lock()
	scs.SessionHits++
	scs.mutex.Unlock()
}

func (scs *SessionCacheStats) recordMiss() {
	scs.mutex.Lock()
	scs.SessionMisses++
	scs.mutex.Unlock()
}

func (scs *SessionCacheStats) recordCreated() {
	scs.mutex.Lock()
	scs.SessionsCreated++
	scs.TotalSessions++
	scs.mutex.Unlock()
}

func (scs *SessionCacheStats) recordExpired() {
	scs.mutex.Lock()
	scs.SessionsExpired++
	if scs.TotalSessions > 0 {
		scs.TotalSessions--
	}
	scs.mutex.Unlock()
}

func (scs *SessionCacheStats) recordTicketKeyRotation() {
	scs.mutex.Lock()
	scs.TicketKeyRotations++
	scs.mutex.Unlock()
}


// Enhanced TLS Config Builder
type TLSConfigBuilder struct {
	sessionCache *SessionCache
	enableDebug  bool
}

// NewTLSConfigBuilder creates a new TLS config builder with session resumption
func NewTLSConfigBuilder(sessionCache *SessionCache, enableDebug bool) *TLSConfigBuilder {
	return &TLSConfigBuilder{
		sessionCache: sessionCache,
		enableDebug:  enableDebug,
	}
}

// BuildClientConfig creates an optimized TLS config for client connections
// DEPRECATED: Use SmartTLSConfig.CreateTLSConfigWithSessionCache instead
func (tcb *TLSConfigBuilder) BuildClientConfig(serverName string, insecureSkipVerify bool) *tls.Config {
	cfg := &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: insecureSkipVerify,
		ClientSessionCache: tcb.sessionCache,

		// Performance optimizations
		PreferServerCipherSuites: false, // Let client choose for better performance
		CurvePreferences: []tls.CurveID{
			tls.X25519,    // Fastest
			tls.CurveP256, // Widely supported
		},
		CipherSuites: []uint16{
			// Prioritize AES-GCM and ChaCha20 for performance
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		},
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,

		// Enable session resumption
		SessionTicketsDisabled: false,
	}

	// Set session ticket keys if available
	if tcb.sessionCache != nil {
		ticketKeys := tcb.sessionCache.GetTicketKeys()
		if len(ticketKeys) > 0 {
			cfg.SetSessionTicketKeys(ticketKeys)
		}
	}

	return cfg
}

// BuildServerConfig creates an optimized TLS config for server connections
func (tcb *TLSConfigBuilder) BuildServerConfig(certificates []tls.Certificate) *tls.Config {
	cfg := &tls.Config{
		Certificates: certificates,

		// Performance optimizations
		PreferServerCipherSuites: true, // Server has better knowledge of its capabilities
		CurvePreferences: []tls.CurveID{
			tls.X25519,    // Fastest
			tls.CurveP256, // Widely supported
		},
		CipherSuites: []uint16{
			// Prioritize AES-GCM and ChaCha20 for performance
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		},
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,

		// Enable session resumption
		SessionTicketsDisabled: false,
	}

	// Set session ticket keys if available
	if tcb.sessionCache != nil {
		ticketKeys := tcb.sessionCache.GetTicketKeys()
		if len(ticketKeys) > 0 {
			cfg.SetSessionTicketKeys(ticketKeys)
		}
	}

	return cfg
}
