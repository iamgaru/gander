package pool

import (
	"sync"
	"sync/atomic"
)

// BufferSize represents different buffer size categories
type BufferSize int

const (
	SmallBuffer  BufferSize = iota // 4KB - for headers, small data
	MediumBuffer                   // 16KB - for moderate payloads
	LargeBuffer                    // 64KB - for large transfers
	HTTPBuffer                     // 8KB - optimized for HTTP parsing
)

// Buffer sizes in bytes
const (
	SmallBufferSize  = 4 * 1024   // 4KB
	MediumBufferSize = 16 * 1024  // 16KB
	LargeBufferSize  = 64 * 1024  // 64KB
	HTTPBufferSize   = 8 * 1024   // 8KB
)

// EnhancedBufferPool provides efficient buffer management with multiple size categories
type EnhancedBufferPool struct {
	smallPool  sync.Pool
	mediumPool sync.Pool
	largePool  sync.Pool
	httpPool   sync.Pool

	// Statistics
	stats BufferPoolStats

	// Configuration
	enableStats bool
}

// BufferPoolStats tracks buffer pool performance
type BufferPoolStats struct {
	SmallBufferGets    int64
	SmallBufferPuts    int64
	MediumBufferGets   int64
	MediumBufferPuts   int64
	LargeBufferGets    int64
	LargeBufferPuts    int64
	HTTPBufferGets     int64
	HTTPBufferPuts     int64
	TotalAllocations   int64
	TotalDeallocations int64
}

// NewEnhancedBufferPool creates a new enhanced buffer pool
func NewEnhancedBufferPool(enableStats bool) *EnhancedBufferPool {
	pool := &EnhancedBufferPool{
		enableStats: enableStats,
	}

	// Initialize pools with factory functions
	pool.smallPool.New = func() interface{} {
		if enableStats {
			atomic.AddInt64(&pool.stats.TotalAllocations, 1)
		}
		return make([]byte, SmallBufferSize)
	}

	pool.mediumPool.New = func() interface{} {
		if enableStats {
			atomic.AddInt64(&pool.stats.TotalAllocations, 1)
		}
		return make([]byte, MediumBufferSize)
	}

	pool.largePool.New = func() interface{} {
		if enableStats {
			atomic.AddInt64(&pool.stats.TotalAllocations, 1)
		}
		return make([]byte, LargeBufferSize)
	}

	pool.httpPool.New = func() interface{} {
		if enableStats {
			atomic.AddInt64(&pool.stats.TotalAllocations, 1)
		}
		return make([]byte, HTTPBufferSize)
	}

	return pool
}

// Get retrieves a buffer of the specified size
func (bp *EnhancedBufferPool) Get(size BufferSize) []byte {
	switch size {
	case SmallBuffer:
		if bp.enableStats {
			atomic.AddInt64(&bp.stats.SmallBufferGets, 1)
		}
		return bp.smallPool.Get().([]byte)
	case MediumBuffer:
		if bp.enableStats {
			atomic.AddInt64(&bp.stats.MediumBufferGets, 1)
		}
		return bp.mediumPool.Get().([]byte)
	case LargeBuffer:
		if bp.enableStats {
			atomic.AddInt64(&bp.stats.LargeBufferGets, 1)
		}
		return bp.largePool.Get().([]byte)
	case HTTPBuffer:
		if bp.enableStats {
			atomic.AddInt64(&bp.stats.HTTPBufferGets, 1)
		}
		return bp.httpPool.Get().([]byte)
	default:
		// Default to medium buffer
		if bp.enableStats {
			atomic.AddInt64(&bp.stats.MediumBufferGets, 1)
		}
		return bp.mediumPool.Get().([]byte)
	}
}

// GetOptimal returns the most appropriate buffer size for the given data size
func (bp *EnhancedBufferPool) GetOptimal(dataSize int) []byte {
	switch {
	case dataSize <= SmallBufferSize:
		return bp.Get(SmallBuffer)
	case dataSize <= MediumBufferSize:
		return bp.Get(MediumBuffer)
	case dataSize <= HTTPBufferSize:
		return bp.Get(HTTPBuffer)
	default:
		return bp.Get(LargeBuffer)
	}
}

// Put returns a buffer to the appropriate pool
func (bp *EnhancedBufferPool) Put(buf []byte) {
	if buf == nil {
		return
	}

	// Clear the buffer for security (zero out any sensitive data)
	for i := range buf {
		buf[i] = 0
	}

	if bp.enableStats {
		atomic.AddInt64(&bp.stats.TotalDeallocations, 1)
	}

	switch len(buf) {
	case SmallBufferSize:
		if bp.enableStats {
			atomic.AddInt64(&bp.stats.SmallBufferPuts, 1)
		}
		bp.smallPool.Put(buf)
	case MediumBufferSize:
		if bp.enableStats {
			atomic.AddInt64(&bp.stats.MediumBufferPuts, 1)
		}
		bp.mediumPool.Put(buf)
	case LargeBufferSize:
		if bp.enableStats {
			atomic.AddInt64(&bp.stats.LargeBufferPuts, 1)
		}
		bp.largePool.Put(buf)
	case HTTPBufferSize:
		if bp.enableStats {
			atomic.AddInt64(&bp.stats.HTTPBufferPuts, 1)
		}
		bp.httpPool.Put(buf)
	default:
		// Don't pool buffers of unexpected sizes
		return
	}
}

// GetStats returns current buffer pool statistics
func (bp *EnhancedBufferPool) GetStats() BufferPoolStats {
	return BufferPoolStats{
		SmallBufferGets:    atomic.LoadInt64(&bp.stats.SmallBufferGets),
		SmallBufferPuts:    atomic.LoadInt64(&bp.stats.SmallBufferPuts),
		MediumBufferGets:   atomic.LoadInt64(&bp.stats.MediumBufferGets),
		MediumBufferPuts:   atomic.LoadInt64(&bp.stats.MediumBufferPuts),
		LargeBufferGets:    atomic.LoadInt64(&bp.stats.LargeBufferGets),
		LargeBufferPuts:    atomic.LoadInt64(&bp.stats.LargeBufferPuts),
		HTTPBufferGets:     atomic.LoadInt64(&bp.stats.HTTPBufferGets),
		HTTPBufferPuts:     atomic.LoadInt64(&bp.stats.HTTPBufferPuts),
		TotalAllocations:   atomic.LoadInt64(&bp.stats.TotalAllocations),
		TotalDeallocations: atomic.LoadInt64(&bp.stats.TotalDeallocations),
	}
}

// GetEfficiency returns buffer pool efficiency metrics
func (bp *EnhancedBufferPool) GetEfficiency() map[string]float64 {
	stats := bp.GetStats()
	
	efficiency := make(map[string]float64)
	
	// Calculate reuse rates for each buffer type
	if stats.SmallBufferGets > 0 {
		efficiency["small_reuse_rate"] = float64(stats.SmallBufferPuts) / float64(stats.SmallBufferGets)
	}
	if stats.MediumBufferGets > 0 {
		efficiency["medium_reuse_rate"] = float64(stats.MediumBufferPuts) / float64(stats.MediumBufferGets)
	}
	if stats.LargeBufferGets > 0 {
		efficiency["large_reuse_rate"] = float64(stats.LargeBufferPuts) / float64(stats.LargeBufferGets)
	}
	if stats.HTTPBufferGets > 0 {
		efficiency["http_reuse_rate"] = float64(stats.HTTPBufferPuts) / float64(stats.HTTPBufferGets)
	}
	
	// Overall reuse rate
	totalGets := stats.SmallBufferGets + stats.MediumBufferGets + stats.LargeBufferGets + stats.HTTPBufferGets
	totalPuts := stats.SmallBufferPuts + stats.MediumBufferPuts + stats.LargeBufferPuts + stats.HTTPBufferPuts
	
	if totalGets > 0 {
		efficiency["overall_reuse_rate"] = float64(totalPuts) / float64(totalGets)
	}
	
	// Memory efficiency (how much we're avoiding allocations)
	if stats.TotalAllocations > 0 {
		efficiency["allocation_efficiency"] = 1.0 - (float64(stats.TotalAllocations) / float64(totalGets))
	}
	
	return efficiency
}

// PooledBuffer provides a RAII-style buffer that automatically returns to pool
type PooledBuffer struct {
	buf  []byte
	pool *EnhancedBufferPool
}

// NewPooledBuffer creates a buffer that will automatically return to the pool when released
func (bp *EnhancedBufferPool) NewPooledBuffer(size BufferSize) *PooledBuffer {
	return &PooledBuffer{
		buf:  bp.Get(size),
		pool: bp,
	}
}

// NewOptimalPooledBuffer creates a buffer of optimal size for the given data size
func (bp *EnhancedBufferPool) NewOptimalPooledBuffer(dataSize int) *PooledBuffer {
	return &PooledBuffer{
		buf:  bp.GetOptimal(dataSize),
		pool: bp,
	}
}

// Bytes returns the underlying buffer
func (pb *PooledBuffer) Bytes() []byte {
	return pb.buf
}

// Len returns the length of the buffer
func (pb *PooledBuffer) Len() int {
	return len(pb.buf)
}

// Cap returns the capacity of the buffer
func (pb *PooledBuffer) Cap() int {
	return cap(pb.buf)
}

// Release returns the buffer to the pool
func (pb *PooledBuffer) Release() {
	if pb.buf != nil {
		pb.pool.Put(pb.buf)
		pb.buf = nil
	}
}

// Slice returns a slice of the buffer with the specified length
func (pb *PooledBuffer) Slice(n int) []byte {
	if n > len(pb.buf) {
		n = len(pb.buf)
	}
	return pb.buf[:n]
}

// HTTPHeaderBuffer provides specialized buffer management for HTTP headers
type HTTPHeaderBuffer struct {
	*PooledBuffer
}

// NewHTTPHeaderBuffer creates a buffer optimized for HTTP header parsing
func (bp *EnhancedBufferPool) NewHTTPHeaderBuffer() *HTTPHeaderBuffer {
	return &HTTPHeaderBuffer{
		PooledBuffer: bp.NewPooledBuffer(HTTPBuffer),
	}
}

// AppendHeader appends an HTTP header to the buffer
func (hb *HTTPHeaderBuffer) AppendHeader(key, value string) {
	if hb.buf != nil {
		header := key + ": " + value + "\r\n"
		if len(hb.buf)+len(header) < cap(hb.buf) {
			hb.buf = append(hb.buf, header...)
		}
	}
}

// Reset clears the buffer for reuse
func (hb *HTTPHeaderBuffer) Reset() {
	if hb.buf != nil {
		hb.buf = hb.buf[:0]
	}
}

// ZeroCopyBuffer provides zero-copy buffer operations where possible
type ZeroCopyBuffer struct {
	*PooledBuffer
	offset int
}

// NewZeroCopyBuffer creates a buffer optimized for zero-copy operations
func (bp *EnhancedBufferPool) NewZeroCopyBuffer(size BufferSize) *ZeroCopyBuffer {
	return &ZeroCopyBuffer{
		PooledBuffer: bp.NewPooledBuffer(size),
		offset:       0,
	}
}

// Read implements io.Reader for zero-copy reading
func (zb *ZeroCopyBuffer) Read(p []byte) (n int, err error) {
	if zb.offset >= len(zb.buf) {
		return 0, nil
	}
	
	available := len(zb.buf) - zb.offset
	n = copy(p, zb.buf[zb.offset:])
	zb.offset += n
	
	if n < len(p) && available > 0 {
		// We couldn't fill the entire slice, so we're at EOF
		return n, nil
	}
	
	return n, nil
}

// Write implements io.Writer for zero-copy writing
func (zb *ZeroCopyBuffer) Write(p []byte) (n int, err error) {
	if len(zb.buf)+len(p) > cap(zb.buf) {
		// Not enough space, copy what we can
		available := cap(zb.buf) - len(zb.buf)
		if available > 0 {
			n = copy(zb.buf[len(zb.buf):cap(zb.buf)], p[:available])
			zb.buf = zb.buf[:len(zb.buf)+n]
		}
		return n, nil
	}
	
	// Enough space for entire write
	n = copy(zb.buf[len(zb.buf):cap(zb.buf)], p)
	zb.buf = zb.buf[:len(zb.buf)+n]
	
	return n, nil
}

// Reset clears the buffer and resets the offset
func (zb *ZeroCopyBuffer) Reset() {
	if zb.buf != nil {
		zb.buf = zb.buf[:0]
		zb.offset = 0
	}
}