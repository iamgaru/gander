package relay

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/iamgaru/gander/internal/cert"
	"github.com/iamgaru/gander/internal/pool"
	tlsopt "github.com/iamgaru/gander/internal/tls"
)

const (
	connectionClose = "close"
)

// ConnectionInfo contains metadata about a proxy connection (duplicated to avoid import cycle)
type ConnectionInfo struct {
	ClientIP     string
	ServerAddr   string
	Domain       string
	Port         string
	Protocol     string
	StartTime    time.Time
	BytesRead    int64
	BytesWritten int64
	IsHTTPS      bool
}

// RelayMode defines different types of relaying
type RelayMode int

const (
	RelayModeFast RelayMode = iota
	RelayModeInspection
	RelayModeTransparent
)

// BufferPool manages reusable byte buffers for performance
type BufferPool struct {
	pool sync.Pool
	size int
}

// NewBufferPool creates a new buffer pool with the specified buffer size
func NewBufferPool(bufferSize int) *BufferPool {
	return &BufferPool{
		pool: sync.Pool{
			New: func() interface{} {
				return make([]byte, bufferSize)
			},
		},
		size: bufferSize,
	}
}

// Get retrieves a buffer from the pool
func (bp *BufferPool) Get() []byte {
	return bp.pool.Get().([]byte)
}

// Put returns a buffer to the pool
func (bp *BufferPool) Put(buf []byte) {
	if len(buf) == bp.size {
		bp.pool.Put(buf)
	}
}

// Relayer handles different types of data relaying
type Relayer struct {
	bufferPool      *pool.EnhancedBufferPool
	connectionPool  *pool.ConnectionPool
	tlsSessionCache *tlsopt.SessionCache
	readTimeout     time.Duration
	writeTimeout    time.Duration
	enableDebug     bool
	certManager     cert.CertificateProvider
	captureHandler  CaptureHandler
	stats           *RelayStats
	smartTLS        *tlsopt.SmartTLSConfig
}

// RelayStats tracks relay performance statistics
type RelayStats struct {
	TotalConnections  int64
	ActiveConnections int64
	FastRelays        int64
	InspectionRelays  int64
	TransparentRelays int64
	HTTPRequests      int64
	HTTPSRequests     int64
	BytesTransferred  int64
	CertificatesUsed  int64
	AverageLatency    int64
	mutex             sync.RWMutex
}

// CaptureHandler interface for HTTP capture functionality
type CaptureHandler interface {
	CaptureHTTPRequest(req *http.Request, clientIP string) error
	CaptureHTTPResponse(resp *http.Response, clientIP string) error
}

// NewEnhancedRelayer creates a new enhanced relayer with connection pooling
func NewEnhancedRelayer(bufferPool *pool.EnhancedBufferPool, connectionPool *pool.ConnectionPool, readTimeout, writeTimeout time.Duration, enableDebug bool) *Relayer {
	return &Relayer{
		bufferPool:     bufferPool,
		connectionPool: connectionPool,
		readTimeout:    readTimeout,
		writeTimeout:   writeTimeout,
		enableDebug:    enableDebug,
		stats:          NewRelayStats(),
		smartTLS:       tlsopt.NewSmartTLSConfig(enableDebug),
	}
}

// NewRelayer creates a new relayer (legacy compatibility)
func NewRelayer(bufferPool *BufferPool, readTimeout, writeTimeout time.Duration, enableDebug bool) *Relayer {
	// Convert old buffer pool to enhanced buffer pool for compatibility
	enhancedPool := pool.NewEnhancedBufferPool(false)

	return &Relayer{
		bufferPool:   enhancedPool,
		readTimeout:  readTimeout,
		writeTimeout: writeTimeout,
		enableDebug:  enableDebug,
		stats:        NewRelayStats(),
		smartTLS:     tlsopt.NewSmartTLSConfig(enableDebug),
	}
}

// SetCertificateManager sets the certificate manager
func (r *Relayer) SetCertificateManager(certManager cert.CertificateProvider) {
	r.certManager = certManager
}

// SetCaptureHandler sets the capture handler
func (r *Relayer) SetCaptureHandler(handler CaptureHandler) {
	r.captureHandler = handler
}

// SetTLSSessionCache sets the TLS session cache
func (r *Relayer) SetTLSSessionCache(cache *tlsopt.SessionCache) {
	r.tlsSessionCache = cache
}

// SetDebug sets the debug flag
func (r *Relayer) SetDebug(enable bool) {
	r.enableDebug = enable
}

// HandleFastRelay performs fast passthrough relay
func (r *Relayer) HandleFastRelay(clientConn net.Conn, serverAddr string, info *ConnectionInfo) error {
	r.stats.IncrementTotal()
	r.stats.IncrementFast()
	defer r.stats.DecrementActive()

	startTime := time.Now()
	defer func() {
		latency := time.Since(startTime).Milliseconds()
		r.stats.UpdateLatency(latency)
	}()

	// Try to get connection from pool first
	var serverConn net.Conn
	var err error

	if r.connectionPool != nil {
		ctx := context.Background()
		serverConn, err = r.connectionPool.GetConnection(ctx, serverAddr, false)
	} else {
		// Fallback to direct connection
		serverConn, err = net.DialTimeout("tcp", serverAddr, 10*time.Second)
	}

	if err != nil {
		return fmt.Errorf("failed to connect to server: %w", err)
	}
	defer serverConn.Close()

	if r.enableDebug {
		log.Printf("Fast relay: %s -> %s", clientConn.RemoteAddr(), serverAddr)
	}

	// Bidirectional relay
	return r.bidirectionalRelay(clientConn, serverConn, info)
}

// HandleTransparentRelay handles transparent proxy relay with initial data
func (r *Relayer) HandleTransparentRelay(clientConn net.Conn, initialData []byte, info *ConnectionInfo) error {
	r.stats.IncrementTotal()
	r.stats.IncrementTransparent()
	defer r.stats.DecrementActive()

	// Try to get connection from pool first
	var serverConn net.Conn
	var err error

	if r.connectionPool != nil {
		ctx := context.Background()
		serverConn, err = r.connectionPool.GetConnection(ctx, info.ServerAddr, false)
	} else {
		// Fallback to direct connection
		serverConn, err = net.DialTimeout("tcp", info.ServerAddr, 10*time.Second)
	}

	if err != nil {
		return fmt.Errorf("failed to connect to server: %w", err)
	}
	defer serverConn.Close()

	// Send initial data if present
	if len(initialData) > 0 {
		if _, err := serverConn.Write(initialData); err != nil {
			return fmt.Errorf("failed to send initial data: %w", err)
		}
		r.stats.AddBytesTransferred(int64(len(initialData)))
	}

	if r.enableDebug {
		log.Printf("Transparent relay: %s -> %s (initial data: %d bytes)",
			clientConn.RemoteAddr(), info.ServerAddr, len(initialData))
	}

	// Bidirectional relay
	return r.bidirectionalRelay(clientConn, serverConn, info)
}

// HandleHTTPRelay handles HTTP relay with optional inspection
func (r *Relayer) HandleHTTPRelay(clientConn net.Conn, initialData []byte, info *ConnectionInfo, inspect bool) error {
	r.stats.IncrementTotal()
	if inspect {
		r.stats.IncrementInspection()
	}
	defer r.stats.DecrementActive()

	r.stats.IncrementHTTP()

	// Create buffered reader with initial data
	var reader io.Reader
	if len(initialData) > 0 {
		reader = io.MultiReader(strings.NewReader(string(initialData)), clientConn)
	} else {
		reader = clientConn
	}

	bufReader := bufio.NewReader(reader)

	for {
		// Parse HTTP request
		req, err := http.ReadRequest(bufReader)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("failed to read HTTP request: %w", err)
		}

		// Capture request if inspection is enabled
		if inspect && r.captureHandler != nil {
			if err := r.captureHandler.CaptureHTTPRequest(req, info.ClientIP); err != nil {
				log.Printf("Failed to capture HTTP request: %v", err)
			}
		}

		// Try to get connection from pool first
		var serverConn net.Conn

		if r.connectionPool != nil {
			ctx := context.Background()
			serverConn, err = r.connectionPool.GetConnection(ctx, info.ServerAddr, false)
		} else {
			// Fallback to direct connection
			serverConn, err = net.DialTimeout("tcp", info.ServerAddr, 10*time.Second)
		}

		if err != nil {
			return fmt.Errorf("failed to connect to server: %w", err)
		}

		// Forward request to server
		if err := req.Write(serverConn); err != nil {
			serverConn.Close()
			return fmt.Errorf("failed to write request to server: %w", err)
		}

		// Read response from server
		serverReader := bufio.NewReader(serverConn)
		resp, err := http.ReadResponse(serverReader, req)
		if err != nil {
			serverConn.Close()
			return fmt.Errorf("failed to read response from server: %w", err)
		}

		// Capture response if inspection is enabled
		if inspect && r.captureHandler != nil {
			if err := r.captureHandler.CaptureHTTPResponse(resp, info.ClientIP); err != nil {
				log.Printf("Failed to capture HTTP response: %v", err)
			}
		}

		// Send response to client
		if err := resp.Write(clientConn); err != nil {
			serverConn.Close()
			return fmt.Errorf("failed to write response to client: %w", err)
		}

		serverConn.Close()

		// Check if connection should be kept alive
		if req.Header.Get("Connection") == connectionClose ||
			resp.Header.Get("Connection") == connectionClose ||
			req.ProtoMajor == 1 && req.ProtoMinor == 0 {
			break
		}
	}

	return nil
}

// HandleHTTPSInspection handles HTTPS with certificate interception
func (r *Relayer) HandleHTTPSInspection(clientConn net.Conn, serverAddr string, info *ConnectionInfo) error {
	r.stats.IncrementTotal()
	r.stats.IncrementInspection()
	r.stats.IncrementHTTPS()
	defer r.stats.DecrementActive()

	if r.certManager == nil {
		// Fallback to transparent relay if no certificate manager
		return r.HandleTransparentRelay(clientConn, nil, info)
	}

	// Get certificate for the domain
	tlsCert, err := r.certManager.GetTLSCertificate(info.Domain)
	if err != nil {
		log.Printf("Failed to get certificate for %s: %v", info.Domain, err)
		// Fallback to transparent relay
		return r.HandleTransparentRelay(clientConn, nil, info)
	}

	r.stats.IncrementCertUsage()

	// Create TLS server configuration
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*tlsCert},
		ServerName:   info.Domain,
	}

	// Perform TLS handshake with client
	tlsClientConn := tls.Server(clientConn, tlsConfig)
	if err := tlsClientConn.Handshake(); err != nil {
		return fmt.Errorf("TLS handshake failed: %w", err)
	}

	if r.enableDebug {
		log.Printf("HTTPS inspection: %s -> %s (domain: %s)",
			clientConn.RemoteAddr(), serverAddr, info.Domain)
	}

	// Create smart TLS config with session resumption
	tlsConfig2 := r.smartTLS.CreateTLSConfigWithSessionCache(info.Domain, tlsopt.TLSContextRelay, r.tlsSessionCache)

	// Set ticket keys for session resumption if session cache is available
	if r.tlsSessionCache != nil {
		ticketKeys := r.tlsSessionCache.GetTicketKeys()
		if len(ticketKeys) > 0 {
			tlsConfig2.SetSessionTicketKeys(ticketKeys)
		}
	}

	// For HTTPS inspection, we need TLS connections with proper domain-specific config
	var serverConn net.Conn
	var isPooled bool

	// Try to get a TLS connection from pool first
	if r.connectionPool != nil {
		ctx := context.Background()
		var poolErr error
		serverConn, poolErr = r.connectionPool.GetConnection(ctx, serverAddr, true)
		if poolErr == nil && serverConn != nil {
			isPooled = true
		}
	}

	// If pool fails or not available, create direct TLS connection
	if serverConn == nil {
		var dialErr error
		serverConn, dialErr = tls.Dial("tcp", serverAddr, tlsConfig2)
		if dialErr != nil {
			return fmt.Errorf("failed to connect to upstream TLS server: %w", dialErr)
		}
		isPooled = false
	}

	// Ensure we have a TLS connection
	var tlsServerConn *tls.Conn
	if isPooled {
		// For pooled connections, we need to check if it's already TLS
		if tlsConn, ok := serverConn.(*tls.Conn); ok {
			tlsServerConn = tlsConn
		} else {
			// If pooled connection is not TLS, we need to upgrade it
			// This shouldn't happen with our current pool implementation, but handle it
			serverConn.Close()
			var tlsErr error
			tlsServerConn, tlsErr = tls.Dial("tcp", serverAddr, tlsConfig2)
			if tlsErr != nil {
				return fmt.Errorf("failed to connect to upstream TLS server: %w", tlsErr)
			}
			serverConn = tlsServerConn
			isPooled = false
		}
	} else {
		// For direct connections, it should already be TLS
		if tlsConn, ok := serverConn.(*tls.Conn); ok {
			tlsServerConn = tlsConn
		} else {
			return fmt.Errorf("expected TLS connection but got non-TLS connection")
		}
	}

	// Close connection appropriately - both pooled and direct connections use Close()
	defer serverConn.Close()

	// Handle as HTTP over the TLS connections
	return r.handleHTTPSTraffic(tlsClientConn, tlsServerConn, info)
}

// handleHTTPSTraffic handles HTTP traffic over TLS connections
func (r *Relayer) handleHTTPSTraffic(clientConn, serverConn *tls.Conn, info *ConnectionInfo) error {
	clientReader := bufio.NewReader(clientConn)
	serverReader := bufio.NewReader(serverConn)

	for {
		// Read HTTP request from client
		req, err := http.ReadRequest(clientReader)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("failed to read HTTPS request: %w", err)
		}

		// Capture request if handler is available
		if r.captureHandler != nil {
			if err := r.captureHandler.CaptureHTTPRequest(req, info.ClientIP); err != nil {
				log.Printf("Failed to capture HTTPS request: %v", err)
			}
		}

		// Forward request to server
		if err := req.Write(serverConn); err != nil {
			return fmt.Errorf("failed to write HTTPS request to server: %w", err)
		}

		// Read response from server using persistent reader
		resp, err := http.ReadResponse(serverReader, req)
		if err != nil {
			return fmt.Errorf("failed to read HTTPS response from server: %w", err)
		}

		// Capture response if handler is available
		if r.captureHandler != nil {
			if err := r.captureHandler.CaptureHTTPResponse(resp, info.ClientIP); err != nil {
				log.Printf("Failed to capture HTTPS response: %v", err)
			}
		}

		// Send response to client
		if err := resp.Write(clientConn); err != nil {
			return fmt.Errorf("failed to write HTTPS response to client: %w", err)
		}

		// Check if connection should be kept alive
		if req.Header.Get("Connection") == connectionClose ||
			resp.Header.Get("Connection") == connectionClose ||
			req.ProtoMajor == 1 && req.ProtoMinor == 0 {
			break
		}
	}

	return nil
}

// bidirectionalRelay performs bidirectional data relay between connections
func (r *Relayer) bidirectionalRelay(clientConn, serverConn net.Conn, info *ConnectionInfo) error {
	// Set timeouts
	if r.readTimeout > 0 {
		if err := clientConn.SetReadDeadline(time.Now().Add(r.readTimeout)); err != nil {
			log.Printf("Failed to set client read deadline: %v", err)
		}
		if err := serverConn.SetReadDeadline(time.Now().Add(r.readTimeout)); err != nil {
			log.Printf("Failed to set server read deadline: %v", err)
		}
	}
	if r.writeTimeout > 0 {
		if err := clientConn.SetWriteDeadline(time.Now().Add(r.writeTimeout)); err != nil {
			log.Printf("Failed to set client write deadline: %v", err)
		}
		if err := serverConn.SetWriteDeadline(time.Now().Add(r.writeTimeout)); err != nil {
			log.Printf("Failed to set server write deadline: %v", err)
		}
	}

	// Use wait group to handle both directions
	var wg sync.WaitGroup
	wg.Add(2)

	// Client to server
	go func() {
		defer wg.Done()
		written, err := r.copyWithBuffer(serverConn, clientConn)
		if err != nil && r.enableDebug {
			log.Printf("Client->Server relay error: %v", err)
		}
		info.BytesRead += written
		r.stats.AddBytesTransferred(written)
		serverConn.Close()
	}()

	// Server to client
	go func() {
		defer wg.Done()
		written, err := r.copyWithBuffer(clientConn, serverConn)
		if err != nil && r.enableDebug {
			log.Printf("Server->Client relay error: %v", err)
		}
		info.BytesWritten += written
		r.stats.AddBytesTransferred(written)
		clientConn.Close()
	}()

	wg.Wait()
	return nil
}

// copyWithBuffer performs buffered copy between connections
func (r *Relayer) copyWithBuffer(dst io.Writer, src io.Reader) (int64, error) {
	pooledBuffer := r.bufferPool.NewPooledBuffer(pool.LargeBuffer)
	defer pooledBuffer.Release()

	buf := pooledBuffer.Bytes()

	var written int64
	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[0:nr])
			if nw > 0 {
				written += int64(nw)
			}
			if ew != nil {
				return written, ew
			}
			if nr != nw {
				return written, io.ErrShortWrite
			}
		}
		if er != nil {
			if er != io.EOF {
				return written, er
			}
			break
		}
	}
	return written, nil
}

// NewRelayStats creates new relay statistics
func NewRelayStats() *RelayStats {
	return &RelayStats{}
}

// IncrementTotal increments total and active connections
func (rs *RelayStats) IncrementTotal() {
	rs.mutex.Lock()
	defer rs.mutex.Unlock()
	rs.TotalConnections++
	rs.ActiveConnections++
}

// DecrementActive decrements active connections
func (rs *RelayStats) DecrementActive() {
	rs.mutex.Lock()
	defer rs.mutex.Unlock()
	if rs.ActiveConnections > 0 {
		rs.ActiveConnections--
	}
}

// IncrementFast increments fast relay count
func (rs *RelayStats) IncrementFast() {
	rs.mutex.Lock()
	defer rs.mutex.Unlock()
	rs.FastRelays++
}

// IncrementInspection increments inspection relay count
func (rs *RelayStats) IncrementInspection() {
	rs.mutex.Lock()
	defer rs.mutex.Unlock()
	rs.InspectionRelays++
}

// IncrementTransparent increments transparent relay count
func (rs *RelayStats) IncrementTransparent() {
	rs.mutex.Lock()
	defer rs.mutex.Unlock()
	rs.TransparentRelays++
}

// IncrementHTTP increments HTTP request count
func (rs *RelayStats) IncrementHTTP() {
	rs.mutex.Lock()
	defer rs.mutex.Unlock()
	rs.HTTPRequests++
}

// IncrementHTTPS increments HTTPS request count
func (rs *RelayStats) IncrementHTTPS() {
	rs.mutex.Lock()
	defer rs.mutex.Unlock()
	rs.HTTPSRequests++
}

// IncrementCertUsage increments certificate usage count
func (rs *RelayStats) IncrementCertUsage() {
	rs.mutex.Lock()
	defer rs.mutex.Unlock()
	rs.CertificatesUsed++
}

// AddBytesTransferred adds to bytes transferred count
func (rs *RelayStats) AddBytesTransferred(bytes int64) {
	rs.mutex.Lock()
	defer rs.mutex.Unlock()
	rs.BytesTransferred += bytes
}

// UpdateLatency updates average latency
func (rs *RelayStats) UpdateLatency(latency int64) {
	rs.mutex.Lock()
	defer rs.mutex.Unlock()
	if rs.AverageLatency == 0 {
		rs.AverageLatency = latency
	} else {
		rs.AverageLatency = (rs.AverageLatency + latency) / 2
	}
}

// RelayStatsSnapshot represents a snapshot of relay statistics without mutex
type RelayStatsSnapshot struct {
	TotalConnections  int64
	ActiveConnections int64
	FastRelays        int64
	InspectionRelays  int64
	TransparentRelays int64
	HTTPRequests      int64
	HTTPSRequests     int64
	BytesTransferred  int64
	CertificatesUsed  int64
	AverageLatency    int64
}

// GetStats returns a copy of current statistics
func (rs *RelayStats) GetStats() RelayStatsSnapshot {
	rs.mutex.RLock()
	defer rs.mutex.RUnlock()
	return RelayStatsSnapshot{
		TotalConnections:  rs.TotalConnections,
		ActiveConnections: rs.ActiveConnections,
		FastRelays:        rs.FastRelays,
		InspectionRelays:  rs.InspectionRelays,
		TransparentRelays: rs.TransparentRelays,
		HTTPRequests:      rs.HTTPRequests,
		HTTPSRequests:     rs.HTTPSRequests,
		BytesTransferred:  rs.BytesTransferred,
		CertificatesUsed:  rs.CertificatesUsed,
		AverageLatency:    rs.AverageLatency,
	}
}
