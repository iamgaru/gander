package pool

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	tlsverify "github.com/iamgaru/gander/internal/tls"
)

// ConnectionPool manages reusable network connections
type ConnectionPool struct {
	pools       map[string]*targetPool
	poolsMutex  sync.RWMutex
	maxPoolSize int
	maxIdleTime time.Duration
	dialTimeout time.Duration
	enableDebug bool
	stats       *PoolStats
	smartTLS    *tlsverify.SmartTLSConfig
}

// targetPool holds connections for a specific target
type targetPool struct {
	target      string
	connections chan *pooledConnection
	created     int
	maxSize     int
}

// pooledConnection wraps a network connection with metadata
type pooledConnection struct {
	conn      net.Conn
	target    string
	createdAt time.Time
	lastUsed  time.Time
	useCount  int
	isTLS     bool
}

// PoolStats tracks connection pool performance
type PoolStats struct {
	mutex              sync.RWMutex
	TotalPools         int
	TotalConnections   int
	ActiveConnections  int
	IdleConnections    int
	PoolHits           int64
	PoolMisses         int64
	ConnectionsCreated int64
	ConnectionsReused  int64
	ConnectionsExpired int64
	ConnectionsClosed  int64
}

// PoolStatsSnapshot represents a snapshot of pool statistics without mutex
type PoolStatsSnapshot struct {
	TotalPools         int
	TotalConnections   int
	ActiveConnections  int
	IdleConnections    int
	PoolHits           int64
	PoolMisses         int64
	ConnectionsCreated int64
	ConnectionsReused  int64
	ConnectionsExpired int64
	ConnectionsClosed  int64
}

// PoolConfig contains connection pool configuration
type PoolConfig struct {
	MaxPoolSize     int
	MaxIdleTime     time.Duration
	DialTimeout     time.Duration
	CleanupInterval time.Duration
	EnableDebug     bool
}

// NewConnectionPool creates a new connection pool
func NewConnectionPool(config *PoolConfig) *ConnectionPool {
	if config.MaxPoolSize == 0 {
		config.MaxPoolSize = 100
	}
	if config.MaxIdleTime == 0 {
		config.MaxIdleTime = 5 * time.Minute
	}
	if config.DialTimeout == 0 {
		config.DialTimeout = 10 * time.Second
	}
	if config.CleanupInterval == 0 {
		config.CleanupInterval = 1 * time.Minute
	}

	pool := &ConnectionPool{
		pools:       make(map[string]*targetPool),
		maxPoolSize: config.MaxPoolSize,
		maxIdleTime: config.MaxIdleTime,
		dialTimeout: config.DialTimeout,
		enableDebug: config.EnableDebug,
		stats:       &PoolStats{},
		smartTLS:    tlsverify.NewSmartTLSConfig(config.EnableDebug),
	}

	// Start cleanup goroutine
	go pool.cleanupWorker(config.CleanupInterval)

	return pool
}

// extractDomainFromTarget extracts the domain/hostname from a target address
func extractDomainFromTarget(target string) string {
	// Remove port if present
	if idx := strings.LastIndex(target, ":"); idx != -1 {
		return target[:idx]
	}
	return target
}

// GetConnection gets a connection from the pool or creates a new one
func (cp *ConnectionPool) GetConnection(ctx context.Context, target string, useTLS bool) (net.Conn, error) {
	// Try to get from pool first
	if conn := cp.getFromPool(target); conn != nil {
		cp.stats.recordHit()
		if cp.enableDebug {
			fmt.Printf("Pool: Reused connection to %s (use count: %d)\n", target, conn.useCount)
		}
		return conn.conn, nil
	}

	cp.stats.recordMiss()

	// Create new connection
	var conn net.Conn
	var err error

	if useTLS {
		// Extract domain from target for smart TLS verification
		domain := extractDomainFromTarget(target)
		tlsConfig := cp.smartTLS.CreateTLSConfig(domain, tlsverify.TLSContextPooling)

		conn, err = tls.DialWithDialer(&net.Dialer{
			Timeout: cp.dialTimeout,
		}, "tcp", target, tlsConfig)
	} else {
		conn, err = net.DialTimeout("tcp", target, cp.dialTimeout)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to dial %s: %w", target, err)
	}

	cp.stats.recordConnectionCreated()

	if cp.enableDebug {
		fmt.Printf("Pool: Created new connection to %s\n", target)
	}

	// Wrap the connection
	pooledConn := &pooledConnection{
		conn:      conn,
		target:    target,
		createdAt: time.Now(),
		lastUsed:  time.Now(),
		useCount:  1,
		isTLS:     useTLS,
	}

	return &poolConnectionWrapper{pooledConnection: pooledConn, pool: cp}, nil
}

// getFromPool tries to get a connection from the pool
func (cp *ConnectionPool) getFromPool(target string) *pooledConnection {
	cp.poolsMutex.RLock()
	pool, exists := cp.pools[target]
	cp.poolsMutex.RUnlock()

	if !exists {
		return nil
	}

	select {
	case conn := <-pool.connections:
		// Check if connection is still valid and not expired
		if time.Since(conn.lastUsed) > cp.maxIdleTime {
			conn.conn.Close()
			cp.stats.recordConnectionExpired()
			return cp.getFromPool(target) // Try again
		}

		// Update usage statistics
		conn.lastUsed = time.Now()
		conn.useCount++
		cp.stats.recordConnectionReused()

		return conn
	default:
		// No connections available in pool
		return nil
	}
}

// ReturnConnection returns a connection to the pool
func (cp *ConnectionPool) ReturnConnection(conn *pooledConnection) {
	if conn == nil {
		return
	}

	// Get or create target pool
	cp.poolsMutex.Lock()
	pool, exists := cp.pools[conn.target]
	if !exists {
		pool = &targetPool{
			target:      conn.target,
			connections: make(chan *pooledConnection, cp.maxPoolSize),
			maxSize:     cp.maxPoolSize,
		}
		cp.pools[conn.target] = pool
	}
	cp.poolsMutex.Unlock()

	// Try to return to pool
	select {
	case pool.connections <- conn:
		if cp.enableDebug {
			fmt.Printf("Pool: Returned connection to %s to pool\n", conn.target)
		}
	default:
		// Pool is full, close the connection
		conn.conn.Close()
		cp.stats.recordConnectionClosed()
		if cp.enableDebug {
			fmt.Printf("Pool: Pool full, closed connection to %s\n", conn.target)
		}
	}
}

// poolConnectionWrapper wraps a pooled connection to handle automatic return
type poolConnectionWrapper struct {
	*pooledConnection
	pool   *ConnectionPool
	closed bool
	mutex  sync.Mutex
}

// Read implements net.Conn
func (pcw *poolConnectionWrapper) Read(b []byte) (n int, err error) {
	return pcw.pooledConnection.conn.Read(b)
}

// Write implements net.Conn
func (pcw *poolConnectionWrapper) Write(b []byte) (n int, err error) {
	return pcw.pooledConnection.conn.Write(b)
}

// Close handles connection cleanup and potential return to pool
func (pcw *poolConnectionWrapper) Close() error {
	pcw.mutex.Lock()
	defer pcw.mutex.Unlock()

	if pcw.closed {
		return nil
	}
	pcw.closed = true

	// Check if connection is still usable for pooling
	if pcw.shouldReturnToPool() {
		pcw.pool.ReturnConnection(pcw.pooledConnection)
		return nil
	}

	// Close the connection
	pcw.pool.stats.recordConnectionClosed()
	return pcw.pooledConnection.conn.Close()
}

// shouldReturnToPool determines if a connection should be returned to the pool
func (pcw *poolConnectionWrapper) shouldReturnToPool() bool {
	// Don't pool if connection is too old
	if time.Since(pcw.pooledConnection.createdAt) > 10*time.Minute {
		return false
	}

	// Don't pool if used too many times
	if pcw.pooledConnection.useCount > 100 {
		return false
	}

	// Don't pool TLS connections that might have state issues
	if pcw.pooledConnection.isTLS && pcw.pooledConnection.useCount > 10 {
		return false
	}

	return true
}

// Implement remaining net.Conn methods
func (pcw *poolConnectionWrapper) LocalAddr() net.Addr {
	return pcw.pooledConnection.conn.LocalAddr()
}

func (pcw *poolConnectionWrapper) RemoteAddr() net.Addr {
	return pcw.pooledConnection.conn.RemoteAddr()
}

func (pcw *poolConnectionWrapper) SetDeadline(t time.Time) error {
	return pcw.pooledConnection.conn.SetDeadline(t)
}

func (pcw *poolConnectionWrapper) SetReadDeadline(t time.Time) error {
	return pcw.pooledConnection.conn.SetReadDeadline(t)
}

func (pcw *poolConnectionWrapper) SetWriteDeadline(t time.Time) error {
	return pcw.pooledConnection.conn.SetWriteDeadline(t)
}

// cleanupWorker periodically cleans up expired connections
func (cp *ConnectionPool) cleanupWorker(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		cp.cleanup()
	}
}

// cleanup removes expired connections from all pools
func (cp *ConnectionPool) cleanup() {
	cp.poolsMutex.RLock()
	pools := make([]*targetPool, 0, len(cp.pools))
	for _, pool := range cp.pools {
		pools = append(pools, pool)
	}
	cp.poolsMutex.RUnlock()

	for _, targetPool := range pools {
		cp.cleanupTargetPool(targetPool)
	}
}

// cleanupTargetPool removes expired connections from a specific target pool
func (cp *ConnectionPool) cleanupTargetPool(targetPool *targetPool) {
	var expiredConns []*pooledConnection

	// Collect expired connections
	for {
		select {
		case conn := <-targetPool.connections:
			if time.Since(conn.lastUsed) > cp.maxIdleTime {
				expiredConns = append(expiredConns, conn)
			} else {
				// Put non-expired connection back
				select {
				case targetPool.connections <- conn:
				default:
					// Pool is full, close connection
					conn.conn.Close()
					cp.stats.recordConnectionClosed()
				}
			}
		default:
			// No more connections in pool
			goto cleanup
		}
	}

cleanup:
	// Close expired connections
	for _, conn := range expiredConns {
		conn.conn.Close()
		cp.stats.recordConnectionExpired()
	}

	if len(expiredConns) > 0 && cp.enableDebug {
		fmt.Printf("Pool: Cleaned up %d expired connections for %s\n",
			len(expiredConns), targetPool.target)
	}
}

// GetStats returns current pool statistics
func (cp *ConnectionPool) GetStats() PoolStatsSnapshot {
	cp.stats.mutex.RLock()
	defer cp.stats.mutex.RUnlock()

	cp.poolsMutex.RLock()
	totalPools := len(cp.pools)
	totalConns := 0
	idleConns := 0

	for _, pool := range cp.pools {
		totalConns += pool.created
		idleConns += len(pool.connections)
	}
	cp.poolsMutex.RUnlock()

	// Create a snapshot without copying the mutex
	stats := PoolStatsSnapshot{
		TotalPools:         totalPools,
		TotalConnections:   totalConns,
		ActiveConnections:  totalConns - idleConns,
		IdleConnections:    idleConns,
		PoolHits:           cp.stats.PoolHits,
		PoolMisses:         cp.stats.PoolMisses,
		ConnectionsCreated: cp.stats.ConnectionsCreated,
		ConnectionsReused:  cp.stats.ConnectionsReused,
		ConnectionsExpired: cp.stats.ConnectionsExpired,
		ConnectionsClosed:  cp.stats.ConnectionsClosed,
	}

	return stats
}

// Close shuts down the connection pool
func (cp *ConnectionPool) Close() error {
	cp.poolsMutex.Lock()
	defer cp.poolsMutex.Unlock()

	for target, targetPool := range cp.pools {
		// Close all connections in the pool
		close(targetPool.connections)
		for conn := range targetPool.connections {
			conn.conn.Close()
		}
		delete(cp.pools, target)
	}

	return nil
}

// Statistics recording methods
func (ps *PoolStats) recordHit() {
	ps.mutex.Lock()
	ps.PoolHits++
	ps.mutex.Unlock()
}

func (ps *PoolStats) recordMiss() {
	ps.mutex.Lock()
	ps.PoolMisses++
	ps.mutex.Unlock()
}

func (ps *PoolStats) recordConnectionCreated() {
	ps.mutex.Lock()
	ps.ConnectionsCreated++
	ps.mutex.Unlock()
}

func (ps *PoolStats) recordConnectionReused() {
	ps.mutex.Lock()
	ps.ConnectionsReused++
	ps.mutex.Unlock()
}

func (ps *PoolStats) recordConnectionExpired() {
	ps.mutex.Lock()
	ps.ConnectionsExpired++
	ps.mutex.Unlock()
}

func (ps *PoolStats) recordConnectionClosed() {
	ps.mutex.Lock()
	ps.ConnectionsClosed++
	ps.mutex.Unlock()
}
