package proxy

import (
	"net"
	"sync"
	"time"
)

// ConnectionInfo contains metadata about a proxy connection
type ConnectionInfo struct {
	ClientIP   string
	ServerAddr string
	Domain     string
	Protocol   string
	StartTime  time.Time
	BytesRead  int64
	BytesWrite int64
	Inspected  bool
	Captured   bool
}

// ProxyStats tracks proxy server statistics
type ProxyStats struct {
	TotalConnections     int64 `json:"total_connections"`
	ActiveConnections    int64 `json:"active_connections"`
	BytesTransferred     int64 `json:"bytes_transferred"`
	InspectedConnections int64 `json:"inspected_connections"`
	CapturedRequests     int64 `json:"captured_requests"`
	mutex                sync.RWMutex
}

// NewProxyStats creates a new ProxyStats instance
func NewProxyStats() *ProxyStats {
	return &ProxyStats{}
}

// IncrementTotal safely increments total connections
func (ps *ProxyStats) IncrementTotal() {
	ps.mutex.Lock()
	defer ps.mutex.Unlock()
	ps.TotalConnections++
}

// IncrementActive safely increments active connections
func (ps *ProxyStats) IncrementActive() {
	ps.mutex.Lock()
	defer ps.mutex.Unlock()
	ps.ActiveConnections++
}

// DecrementActive safely decrements active connections
func (ps *ProxyStats) DecrementActive() {
	ps.mutex.Lock()
	defer ps.mutex.Unlock()
	ps.ActiveConnections--
}

// IncrementInspected safely increments inspected connections
func (ps *ProxyStats) IncrementInspected() {
	ps.mutex.Lock()
	defer ps.mutex.Unlock()
	ps.InspectedConnections++
}

// IncrementCaptured safely increments captured requests
func (ps *ProxyStats) IncrementCaptured() {
	ps.mutex.Lock()
	defer ps.mutex.Unlock()
	ps.CapturedRequests++
}

// AddBytesTransferred safely adds to bytes transferred
func (ps *ProxyStats) AddBytesTransferred(bytes int64) {
	ps.mutex.Lock()
	defer ps.mutex.Unlock()
	ps.BytesTransferred += bytes
}

// ProxyStatsSnapshot represents a snapshot of proxy statistics without mutex
type ProxyStatsSnapshot struct {
	TotalConnections     int64 `json:"total_connections"`
	ActiveConnections    int64 `json:"active_connections"`
	BytesTransferred     int64 `json:"bytes_transferred"`
	InspectedConnections int64 `json:"inspected_connections"`
	CapturedRequests     int64 `json:"captured_requests"`
}

// GetStats returns a copy of current statistics
func (ps *ProxyStats) GetStats() ProxyStatsSnapshot {
	ps.mutex.RLock()
	defer ps.mutex.RUnlock()
	return ProxyStatsSnapshot{
		TotalConnections:     ps.TotalConnections,
		ActiveConnections:    ps.ActiveConnections,
		BytesTransferred:     ps.BytesTransferred,
		InspectedConnections: ps.InspectedConnections,
		CapturedRequests:     ps.CapturedRequests,
	}
}

// BufferPool manages reusable byte buffers for performance
type BufferPool struct {
	pool *sync.Pool
}

// NewBufferPool creates a new buffer pool with the specified buffer size
func NewBufferPool(bufferSize int) *BufferPool {
	return &BufferPool{
		pool: &sync.Pool{
			New: func() interface{} {
				return make([]byte, bufferSize)
			},
		},
	}
}

// Get retrieves a buffer from the pool
func (bp *BufferPool) Get() []byte {
	return bp.pool.Get().([]byte)
}

// Put returns a buffer to the pool
func (bp *BufferPool) Put(buffer []byte) {
	bp.pool.Put(buffer)
}

// ConnHandler represents a connection handler interface
type ConnHandler interface {
	HandleConnection(clientConn net.Conn, info *ConnectionInfo) error
}

// RelayMode represents different relay modes
type RelayMode int

const (
	RelayModeFast RelayMode = iota
	RelayModeInspection
	RelayModeHTTPS
)

// String returns the string representation of RelayMode
func (rm RelayMode) String() string {
	switch rm {
	case RelayModeFast:
		return "fast"
	case RelayModeInspection:
		return "inspection"
	case RelayModeHTTPS:
		return "https"
	default:
		return "unknown"
	}
}
