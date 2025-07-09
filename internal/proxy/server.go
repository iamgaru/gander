package proxy

import (
	"bytes"
	"context"
	"io"
	"log"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/iamgaru/gander/internal/capture"
	"github.com/iamgaru/gander/internal/cert"
	"github.com/iamgaru/gander/internal/config"
	"github.com/iamgaru/gander/internal/filter"
	"github.com/iamgaru/gander/internal/pool"
	"github.com/iamgaru/gander/internal/relay"
	tlsopt "github.com/iamgaru/gander/internal/tls"
	"github.com/iamgaru/gander/internal/worker"
	"github.com/iamgaru/gander/pkg/protocol"
)

// Server represents the main proxy server
type Server struct {
	config        *config.Config
	filterManager *filter.Manager
	stats         *ProxyStats

	// Core components - Enhanced
	bufferPool      *pool.EnhancedBufferPool
	connectionPool  *pool.ConnectionPool
	workerPool      *worker.WorkerPool
	tlsSessionCache *tlsopt.SessionCache
	certManager     cert.CertificateProvider
	certPreGenMgr   *cert.PreGenerationManager
	relayer         *relay.Relayer
	captureManager  *capture.CaptureManager

	// Runtime state
	logFile    *os.File
	shutdownCh chan struct{}

	// Listeners
	httpListener  net.Listener
	httpsListener net.Listener
}

// NewServer creates a new proxy server
func NewServer(cfg *config.Config, filterManager *filter.Manager) (*Server, error) {
	// Open log file
	logFile, err := os.OpenFile(cfg.Logging.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, err
	}

	// Create enhanced buffer pool
	bufferPool := pool.NewEnhancedBufferPool(cfg.Performance.BufferPool.EnableStats)

	// Create connection pool
	connectionPoolConfig := &pool.PoolConfig{
		MaxPoolSize:     cfg.Performance.ConnectionPool.MaxPoolSize,
		MaxIdleTime:     time.Duration(cfg.Performance.ConnectionPool.MaxIdleTime) * time.Minute,
		DialTimeout:     10 * time.Second,
		CleanupInterval: time.Duration(cfg.Performance.ConnectionPool.CleanupInterval) * time.Minute,
		EnableDebug:     cfg.Logging.EnableDebug,
	}
	connectionPool := pool.NewConnectionPool(connectionPoolConfig)

	// Create TLS session cache
	tlsSessionCacheConfig := &tlsopt.SessionCacheConfig{
		MaxSessions:       cfg.Performance.TLSSessionCache.MaxSessions,
		SessionTTL:        time.Duration(cfg.Performance.TLSSessionCache.SessionTTLHours) * time.Hour,
		TicketKeyRotation: time.Duration(cfg.Performance.TLSSessionCache.TicketKeyRotationHr) * time.Hour,
		CleanupInterval:   5 * time.Minute,
		EnableDebug:       cfg.Logging.EnableDebug,
		EnableClientCache: true,
		EnableServerCache: true,
	}
	tlsSessionCache := tlsopt.NewSessionCache(tlsSessionCacheConfig)

	// Create worker pool
	workerPoolConfig := &worker.WorkerPoolConfig{
		WorkerCount:     cfg.Performance.WorkerPool.WorkerCount,
		QueueSize:       cfg.Performance.WorkerPool.QueueSize,
		EnableDebug:     cfg.Logging.EnableDebug,
		JobTimeout:      time.Duration(cfg.Performance.WorkerPool.JobTimeoutSec) * time.Second,
		ShutdownTimeout: 10 * time.Second,
	}
	if workerPoolConfig.WorkerCount == 0 {
		workerPoolConfig.WorkerCount = runtime.NumCPU() * 2
	}
	workerPool := worker.NewWorkerPool(workerPoolConfig)

	stats := NewProxyStats()

	// Initialize certificate manager
	certManager := cert.NewCertificateManager(cfg.Logging.EnableDebug)

	// Set TLS session cache on certificate manager
	if tlsSessionCache != nil && cfg.Performance.TLSSessionCache.Enabled {
		certManager.SetTLSSessionCache(tlsSessionCache)
	}

	if cfg.TLS.AutoGenerate {
		// Set default certificate details
		organization := "Gamu Corporation"
		country := "US"
		province := "CA"
		locality := "San Francisco"
		commonName := ""

		// Use custom details if provided
		if cfg.TLS.CustomDetails != nil {
			if len(cfg.TLS.CustomDetails.Organization) > 0 {
				organization = cfg.TLS.CustomDetails.Organization[0]
			}
			if len(cfg.TLS.CustomDetails.Country) > 0 {
				country = cfg.TLS.CustomDetails.Country[0]
			}
			if len(cfg.TLS.CustomDetails.Province) > 0 {
				province = cfg.TLS.CustomDetails.Province[0]
			}
			if len(cfg.TLS.CustomDetails.Locality) > 0 {
				locality = cfg.TLS.CustomDetails.Locality[0]
			}
			if cfg.TLS.CustomDetails.CommonName != "" {
				commonName = cfg.TLS.CustomDetails.CommonName
			}
		}

		certConfig := &cert.CertConfig{
			CertFile:          cfg.TLS.CertFile,
			KeyFile:           cfg.TLS.KeyFile,
			CAFile:            cfg.TLS.CAFile,
			CAKeyFile:         cfg.TLS.CAKeyFile,
			CertDir:           cfg.TLS.CertDir,
			AutoGenerate:      cfg.TLS.AutoGenerate,
			ValidDays:         cfg.TLS.ValidDays,
			UpstreamCertSniff: cfg.TLS.UpstreamCertSniff,
			KeySize:           2048,
			Organization:      organization,
			Country:           country,
			Province:          province,
			Locality:          locality,
			CustomCommonName:  commonName,
		}

		if err := certManager.Initialize(certConfig); err != nil {
			return nil, err
		}
	}

	// Initialize certificate pre-generation manager
	certPreGenConfig := &cert.PreGenerationConfig{
		Enabled:            cfg.Performance.CertPreGeneration.Enabled,
		WorkerCount:        cfg.Performance.CertPreGeneration.WorkerCount,
		QueueSize:          1000,
		PopularDomainCount: cfg.Performance.CertPreGeneration.PopularDomainCount,
		FrequencyThreshold: cfg.Performance.CertPreGeneration.FrequencyThreshold,
		PreGenInterval:     10 * time.Minute,
		DomainTTL:          24 * time.Hour,
		StaticDomains:      cfg.Performance.CertPreGeneration.StaticDomains,
		EnableFreqTracking: cfg.Performance.CertPreGeneration.EnableFreqTracking,
		MaxConcurrentGens:  10,
	}
	certPreGenMgr := cert.NewPreGenerationManager(certManager, certPreGenConfig, cfg.Logging.EnableDebug)

	// Initialize relayer with enhanced components
	relayer := relay.NewEnhancedRelayer(
		bufferPool,
		connectionPool,
		time.Duration(cfg.Proxy.ReadTimeout)*time.Second,
		time.Duration(cfg.Proxy.WriteTimeout)*time.Second,
		cfg.Logging.EnableDebug,
	)
	relayer.SetCertificateManager(certManager)
	relayer.SetTLSSessionCache(tlsSessionCache)

	// Initialize capture manager
	captureManager := capture.NewCaptureManager(cfg.Logging.CaptureDir, cfg.Logging.EnableDebug)
	if err := captureManager.Initialize(); err != nil {
		return nil, err
	}
	relayer.SetCaptureHandler(captureManager)

	server := &Server{
		config:          cfg,
		filterManager:   filterManager,
		stats:           stats,
		bufferPool:      bufferPool,
		connectionPool:  connectionPool,
		workerPool:      workerPool,
		tlsSessionCache: tlsSessionCache,
		certManager:     certManager,
		certPreGenMgr:   certPreGenMgr,
		relayer:         relayer,
		captureManager:  captureManager,
		logFile:         logFile,
		shutdownCh:      make(chan struct{}),
	}

	return server, nil
}

// Start starts the proxy server
func (s *Server) Start() error {
	// Start worker pool if enabled
	if s.config.Performance.WorkerPool.Enabled {
		if err := s.workerPool.Start(); err != nil {
			return err
		}
	}

	// Start TLS session cache if enabled
	if s.config.Performance.TLSSessionCache.Enabled {
		// Session cache starts automatically in NewSessionCache
		log.Printf("TLS session cache enabled with %d max sessions", s.config.Performance.TLSSessionCache.MaxSessions)
	}

	// Start certificate pre-generation if enabled
	if s.config.Performance.CertPreGeneration.Enabled {
		if err := s.certPreGenMgr.Start(); err != nil {
			log.Printf("Failed to start certificate pre-generation: %v", err)
		} else {
			log.Printf("Certificate pre-generation started")
		}
	}

	// Start HTTP listener
	httpListener, err := net.Listen("tcp", s.config.Proxy.ListenAddr)
	if err != nil {
		return err
	}
	s.httpListener = httpListener

	log.Printf("Proxy server listening on %s", s.config.Proxy.ListenAddr)

	// Start statistics reporting
	go s.reportStats()

	// Accept connections with worker pool
	if s.config.Performance.WorkerPool.Enabled {
		go s.acceptConnectionsWithWorkerPool(httpListener)
	} else {
		go s.acceptConnections(httpListener)
	}

	return nil
}

// Stop stops the proxy server
func (s *Server) Stop() error {
	close(s.shutdownCh)

	// Stop worker pool
	if s.workerPool != nil && s.config.Performance.WorkerPool.Enabled {
		if err := s.workerPool.Stop(10 * time.Second); err != nil {
			log.Printf("Worker pool stop error: %v", err)
		}
	}

	// Stop certificate pre-generation
	if s.certPreGenMgr != nil && s.config.Performance.CertPreGeneration.Enabled {
		if err := s.certPreGenMgr.Stop(); err != nil {
			log.Printf("Certificate pre-generation stop error: %v", err)
		}
	}

	// Close connection pool
	if s.connectionPool != nil {
		if err := s.connectionPool.Close(); err != nil {
			log.Printf("Connection pool close error: %v", err)
		}
	}

	// Clear TLS session cache
	if s.tlsSessionCache != nil {
		cleared := s.tlsSessionCache.Clear()
		log.Printf("Cleared %d TLS sessions", cleared)
	}

	if s.httpListener != nil {
		s.httpListener.Close()
	}
	if s.httpsListener != nil {
		s.httpsListener.Close()
	}
	if s.logFile != nil {
		s.logFile.Close()
	}
	if s.certManager != nil {
		_ = s.certManager.Shutdown()
	}

	log.Println("Proxy server stopped")
	return nil
}

// acceptConnections accepts and handles incoming connections
func (s *Server) acceptConnections(listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-s.shutdownCh:
				return
			default:
				log.Printf("Accept error: %v", err)
				continue
			}
		}

		go s.handleConnection(conn)
	}
}

// acceptConnectionsWithWorkerPool accepts connections and distributes them to worker pool
func (s *Server) acceptConnectionsWithWorkerPool(listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-s.shutdownCh:
				return
			default:
				log.Printf("Accept error: %v", err)
				continue
			}
		}

		// Submit connection to worker pool
		handler := &connectionHandler{server: s}
		if err := s.workerPool.SubmitConnection(conn, handler); err != nil {
			log.Printf("Failed to submit connection to worker pool: %v", err)
			conn.Close()
		}
	}
}

// connectionHandler implements worker.ConnectionHandler
type connectionHandler struct {
	server *Server
}

// HandleConnection processes a connection using the existing handleConnection logic
func (ch *connectionHandler) HandleConnection(conn net.Conn) error {
	ch.server.handleConnection(conn)
	return nil
}

// handleConnection handles a single client connection
func (s *Server) handleConnection(clientConn net.Conn) {
	defer clientConn.Close()
	s.stats.IncrementActive()
	defer s.stats.DecrementActive()

	// Create connection info
	info := &relay.ConnectionInfo{
		ClientIP:  clientConn.RemoteAddr().String(),
		StartTime: time.Now(),
	}

	// Read initial data to determine protocol using enhanced buffer pool
	pooledBuffer := s.bufferPool.NewPooledBuffer(pool.SmallBuffer)
	defer pooledBuffer.Release()

	buffer := pooledBuffer.Slice(1024)
	n, err := clientConn.Read(buffer)
	if err != nil {
		log.Printf("Failed to read initial data: %v", err)
		return
	}

	data := buffer[:n]

	// Detect protocol and extract connection information
	if protocol.IsHTTPRequest(data) {
		s.handleHTTPConnection(clientConn, data, info)
	} else if protocol.IsTLSHandshake(data) {
		s.handleTLSConnection(clientConn, data, info)
	} else {
		s.handleUnknownConnection(clientConn, data, info)
	}
}

// handleHTTPConnection handles HTTP connections
func (s *Server) handleHTTPConnection(clientConn net.Conn, data []byte, info *relay.ConnectionInfo) {
	// Check if this is a CONNECT request (for HTTPS through proxy)
	if bytes.HasPrefix(data, []byte("CONNECT ")) {
		s.handleCONNECTRequest(clientConn, data, info)
		return
	}

	// Extract host for regular HTTP requests
	host, serverAddr := s.extractHostAndServerAddr(data)
	if host == "" {
		log.Printf("Failed to extract host from HTTP request")
		return
	}

	info.Domain = host
	info.ServerAddr = serverAddr
	info.Protocol = "HTTP"

	// Record domain access for pre-generation tracking
	if s.certPreGenMgr != nil && s.config.Performance.CertPreGeneration.EnableFreqTracking {
		s.certPreGenMgr.RecordDomainAccess(host)
	}

	// Apply filters
	ctx := context.Background()
	filterCtx := &filter.FilterContext{
		ClientIP:   net.ParseIP(info.ClientIP),
		ServerAddr: info.ServerAddr,
		Domain:     info.Domain,
		Protocol:   info.Protocol,
		IsHTTPS:    false,
	}

	decision, err := s.filterManager.ProcessPacket(ctx, filterCtx)
	if err != nil {
		log.Printf("Filter error: %v", err)
		return
	}

	switch decision.Result {
	case filter.FilterBlock:
		log.Printf("Blocked HTTP connection: %s -> %s", info.ClientIP, info.Domain)
		return
	case filter.FilterBypass:
		_ = s.relayer.HandleHTTPRelay(clientConn, data, info, false)
	case filter.FilterInspect, filter.FilterCapture:
		s.stats.IncrementInspected()
		_ = s.relayer.HandleHTTPRelay(clientConn, data, info, true)
	default:
		_ = s.relayer.HandleHTTPRelay(clientConn, data, info, false)
	}

	// Log connection
	s.logConnection(info)
}

// handleTLSConnection handles TLS/HTTPS connections
func (s *Server) handleTLSConnection(clientConn net.Conn, data []byte, info *relay.ConnectionInfo) {
	// Extract SNI from TLS handshake
	sni := protocol.ExtractSNI(data)
	if sni == "" {
		log.Printf("Failed to extract SNI from TLS handshake")
		return
	}

	info.Domain = sni
	info.ServerAddr = sni + ":443"
	info.Protocol = "HTTPS"

	// Record domain access for pre-generation tracking
	if s.certPreGenMgr != nil && s.config.Performance.CertPreGeneration.EnableFreqTracking {
		s.certPreGenMgr.RecordDomainAccess(sni)
	}

	// Apply filters
	ctx := context.Background()
	filterCtx := &filter.FilterContext{
		ClientIP:   net.ParseIP(info.ClientIP),
		ServerAddr: info.ServerAddr,
		Domain:     info.Domain,
		Protocol:   info.Protocol,
		IsHTTPS:    true,
	}

	decision, err := s.filterManager.ProcessPacket(ctx, filterCtx)
	if err != nil {
		log.Printf("Filter error: %v", err)
		return
	}

	switch decision.Result {
	case filter.FilterBlock:
		log.Printf("Blocked HTTPS connection: %s -> %s", info.ClientIP, info.Domain)
		return
	case filter.FilterBypass:
		_ = s.relayer.HandleTransparentRelay(clientConn, data, info)
	case filter.FilterInspect, filter.FilterCapture:
		s.stats.IncrementInspected()
		// Filter manager already decided - perform HTTPS inspection
		_ = s.relayer.HandleHTTPSInspection(clientConn, info.ServerAddr, info)
	default:
		_ = s.relayer.HandleTransparentRelay(clientConn, data, info)
	}

	// Log connection
	s.logConnection(info)
}

// handleUnknownConnection handles unknown protocol connections
func (s *Server) handleUnknownConnection(_ net.Conn, _ []byte, info *relay.ConnectionInfo) {
	info.Protocol = "UNKNOWN"

	// For unknown protocols, try to extract destination from transparent proxy
	// This is a simplified approach - real implementation would use SO_ORIGINAL_DST
	log.Printf("Unknown protocol from %s, closing connection", info.ClientIP)
}

// handleCONNECTRequest handles HTTP CONNECT requests for HTTPS proxy tunneling
func (s *Server) handleCONNECTRequest(clientConn net.Conn, data []byte, info *relay.ConnectionInfo) {
	// Parse CONNECT request
	lines := bytes.Split(data, []byte("\r\n"))
	if len(lines) == 0 {
		log.Printf("Invalid CONNECT request")
		return
	}

	requestLine := string(lines[0])
	parts := strings.Fields(requestLine)
	if len(parts) < 2 {
		log.Printf("Invalid CONNECT request line: %s", requestLine)
		return
	}

	target := parts[1] // e.g., "mail.google.com:443"

	// Extract domain without port for filtering
	host := target
	if colonIdx := strings.LastIndex(target, ":"); colonIdx != -1 {
		host = target[:colonIdx]
	}

	info.Domain = host
	info.ServerAddr = target
	info.Protocol = "HTTPS"

	// Record domain access for pre-generation tracking
	if s.certPreGenMgr != nil && s.config.Performance.CertPreGeneration.EnableFreqTracking {
		s.certPreGenMgr.RecordDomainAccess(host)
	}

	// Apply filters
	ctx := context.Background()
	filterCtx := &filter.FilterContext{
		ClientIP:   net.ParseIP(info.ClientIP),
		ServerAddr: info.ServerAddr,
		Domain:     info.Domain,
		Protocol:   info.Protocol,
		IsHTTPS:    true,
	}

	decision, err := s.filterManager.ProcessPacket(ctx, filterCtx)
	if err != nil {
		log.Printf("Filter error: %v", err)
		return
	}

	switch decision.Result {
	case filter.FilterBlock:
		log.Printf("Blocked HTTPS connection: %s -> %s", info.ClientIP, info.Domain)
		// Send error response
		_, _ = clientConn.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
		return

	case filter.FilterBypass:
		// Transparent proxy - establish tunnel without inspection
		s.handleTransparentTunnel(clientConn, target, info)

	case filter.FilterInspect, filter.FilterCapture:
		s.stats.IncrementInspected()
		// MITM inspection - intercept with custom certificate
		s.handleMITMTunnel(clientConn, target, info)

	default:
		// Default to transparent tunnel
		s.handleTransparentTunnel(clientConn, target, info)
	}

	// Log connection
	s.logConnection(info)
}

// handleTransparentTunnel establishes a transparent HTTPS tunnel
func (s *Server) handleTransparentTunnel(clientConn net.Conn, target string, _ *relay.ConnectionInfo) {
	// Connect to target server
	serverConn, err := net.Dial("tcp", target)
	if err != nil {
		log.Printf("Failed to connect to %s: %v", target, err)
		_, _ = clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer serverConn.Close()

	// Send 200 Connection established
	_, err = clientConn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
	if err != nil {
		log.Printf("Failed to send CONNECT response: %v", err)
		return
	}

	// Start bidirectional relay
	go s.copyData(clientConn, serverConn, "client->server")
	s.copyData(serverConn, clientConn, "server->client")
}

// handleMITMTunnel establishes a MITM tunnel with certificate interception
func (s *Server) handleMITMTunnel(clientConn net.Conn, target string, info *relay.ConnectionInfo) {
	// Send 200 Connection established to make client think tunnel is ready
	_, err := clientConn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
	if err != nil {
		log.Printf("Failed to send CONNECT response: %v", err)
		return
	}

	// Mark as inspected since we're doing MITM
	info.BytesRead = 1 // Mark as inspected
	info.BytesWritten = 1

	// Use the relayer to handle HTTPS inspection with proper MITM
	_ = s.relayer.HandleHTTPSInspection(clientConn, target, info)
}

// copyData copies data between two connections
func (s *Server) copyData(dst, src net.Conn, direction string) {
	defer dst.Close()
	defer src.Close()

	pooledBuffer := s.bufferPool.NewPooledBuffer(pool.LargeBuffer)
	defer pooledBuffer.Release()

	_, err := io.CopyBuffer(dst, src, pooledBuffer.Bytes())
	if err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
		log.Printf("Error copying data (%s): %v", direction, err)
	}
}

// extractHostAndServerAddr extracts host and server address from HTTP request
// Handles CONNECT requests properly to avoid double port assignment
func (s *Server) extractHostAndServerAddr(data []byte) (string, string) {
	// For regular HTTP requests, extract from Host header
	host := protocol.ExtractHTTPHost(data)
	if host == "" {
		return "", ""
	}

	// Check if host already includes port
	if strings.Contains(host, ":") {
		// Host already has port, use as-is
		hostOnly := host
		if colonIdx := strings.LastIndex(host, ":"); colonIdx != -1 {
			hostOnly = host[:colonIdx]
		}
		return hostOnly, host
	}

	// No port specified, add default HTTP port
	return host, host + ":80"
}

// logConnection logs connection information
func (s *Server) logConnection(info *relay.ConnectionInfo) {
	duration := time.Since(info.StartTime)
	logEntry := "[" + time.Now().Format("2006-01-02 15:04:05.000") + "] " +
		info.ClientIP + " -> " + info.ServerAddr + " (" + info.Domain + ") | " +
		duration.String() + " | " +
		strconv.FormatInt(info.BytesRead, 10) + "/" + strconv.FormatInt(info.BytesWritten, 10) + " bytes | " +
		info.Protocol + " | inspected=" +
		func() string {
			if info.BytesRead > 0 || info.BytesWritten > 0 {
				return "true"
			}
			return "false"
		}()

	// Write to log file
	if s.logFile != nil {
		_, _ = s.logFile.WriteString(logEntry + "\n")
	}
}

// reportStats periodically reports statistics
func (s *Server) reportStats() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			proxyStats := s.stats.GetStats()
			captureStats := s.captureManager.GetStats()
			certStats := s.certManager.GetStats()

			// Enhanced statistics reporting
			log.Printf("Proxy Stats: %d total, %d active, %d inspected | Capture: %d requests, %d responses, %d pairs | Certs: %d generated, %d cached",
				proxyStats.TotalConnections,
				proxyStats.ActiveConnections,
				proxyStats.InspectedConnections,
				captureStats.RequestsCaptured,
				captureStats.ResponsesCaptured,
				captureStats.PairsCaptured,
				certStats.GeneratedCerts,
				certStats.CachedCerts,
			)

			// Connection pool stats
			if s.connectionPool != nil {
				poolStats := s.connectionPool.GetStats()
				log.Printf("Connection Pool: %d pools, %d total conns, %d active, %d idle | Hits: %d, Misses: %d, Hit Rate: %.1f%%",
					poolStats.TotalPools,
					poolStats.TotalConnections,
					poolStats.ActiveConnections,
					poolStats.IdleConnections,
					poolStats.PoolHits,
					poolStats.PoolMisses,
					float64(poolStats.PoolHits)*100/float64(poolStats.PoolHits+poolStats.PoolMisses+1),
				)
			}

			// Worker pool stats
			if s.workerPool != nil && s.config.Performance.WorkerPool.Enabled {
				workerStats := s.workerPool.GetStats()
				log.Printf("Worker Pool: %d active, %d idle, %d queued | Processed: %d, Failed: %d, Avg Latency: %dms",
					workerStats.ActiveWorkers,
					workerStats.IdleWorkers,
					workerStats.CurrentQueueLen,
					workerStats.ProcessedJobs,
					workerStats.FailedJobs,
					workerStats.AverageLatency,
				)
			}

			// TLS session cache stats
			if s.tlsSessionCache != nil && s.config.Performance.TLSSessionCache.Enabled {
				sessionStats := s.tlsSessionCache.GetStats()
				log.Printf("TLS Sessions: %d active, %d hits, %d misses | Resumption Rate: %.1f%%",
					sessionStats.ActiveSessions,
					sessionStats.SessionHits,
					sessionStats.SessionMisses,
					sessionStats.ResumptionRate*100,
				)
			}

			// Certificate pre-generation stats
			if s.certPreGenMgr != nil && s.config.Performance.CertPreGeneration.Enabled {
				preGenStats := s.certPreGenMgr.GetStats()
				log.Printf("Cert PreGen: %d generated, %d queued, %d popular domains | Utilization: %.1f%%",
					preGenStats.TotalPreGenerated,
					preGenStats.QueuedDomains,
					preGenStats.PopularDomainCount,
					preGenStats.WorkerUtilization*100,
				)
			}

			// Buffer pool efficiency
			if s.bufferPool != nil {
				efficiency := s.bufferPool.GetEfficiency()
				if overall, ok := efficiency["overall_reuse_rate"]; ok {
					log.Printf("Buffer Pool: %.1f%% reuse rate", overall*100)
				}
			}

		case <-s.shutdownCh:
			return
		}
	}
}

// GetStats returns server statistics
func (s *Server) GetStats() map[string]interface{} {
	proxyStats := s.stats.GetStats()
	captureStats := s.captureManager.GetStats()
	certStats := s.certManager.GetStats()

	result := map[string]interface{}{
		"proxy":   proxyStats,
		"capture": captureStats,
		"certs":   certStats,
	}

	// Add performance statistics
	if s.connectionPool != nil {
		result["connection_pool"] = s.connectionPool.GetStats()
	}

	if s.workerPool != nil && s.config.Performance.WorkerPool.Enabled {
		result["worker_pool"] = s.workerPool.GetStats()
	}

	if s.tlsSessionCache != nil && s.config.Performance.TLSSessionCache.Enabled {
		result["tls_sessions"] = s.tlsSessionCache.GetStats()
	}

	if s.certPreGenMgr != nil && s.config.Performance.CertPreGeneration.Enabled {
		result["cert_pregeneration"] = s.certPreGenMgr.GetStats()
	}

	if s.bufferPool != nil {
		result["buffer_pool"] = s.bufferPool.GetStats()
		result["buffer_efficiency"] = s.bufferPool.GetEfficiency()
	}

	return result
}

// ReloadConfig reloads the server configuration
func (s *Server) ReloadConfig(newConfig *config.Config) error {
	log.Printf("Reloading server configuration...")

	// Update configuration
	oldConfig := s.config
	s.config = newConfig

	// Update debug settings for existing components
	if s.relayer != nil {
		s.relayer.SetDebug(newConfig.Logging.EnableDebug)
	}

	// Update filter manager if rules changed
	if s.rulesChanged(oldConfig.Rules, newConfig.Rules) {
		if err := s.reloadFilterManager(newConfig); err != nil {
			log.Printf("Failed to reload filter manager: %v", err)
			// Revert config on failure
			s.config = oldConfig
			return err
		}
	}

	// Update certificate manager if TLS settings changed
	if oldConfig.TLS != newConfig.TLS {
		if err := s.reloadCertificateManager(newConfig); err != nil {
			log.Printf("Failed to reload certificate manager: %v", err)
			// Revert config on failure
			s.config = oldConfig
			return err
		}
	}

	// Update capture manager if logging settings changed
	if oldConfig.Logging.CaptureDir != newConfig.Logging.CaptureDir {
		if err := s.reloadCaptureManager(newConfig); err != nil {
			log.Printf("Failed to reload capture manager: %v", err)
			// Revert config on failure
			s.config = oldConfig
			return err
		}
	}

	log.Printf("Server configuration reloaded successfully")
	return nil
}

// reloadCertificateManager reinitializes the certificate manager with new config
func (s *Server) reloadCertificateManager(cfg *config.Config) error {
	if !cfg.TLS.AutoGenerate {
		return nil
	}

	// Set default certificate details
	organization := "Gamu Corporation"
	country := "US"
	province := "CA"
	locality := "San Francisco"
	commonName := ""

	// Use custom details if provided
	if cfg.TLS.CustomDetails != nil {
		if len(cfg.TLS.CustomDetails.Organization) > 0 {
			organization = cfg.TLS.CustomDetails.Organization[0]
		}
		if len(cfg.TLS.CustomDetails.Country) > 0 {
			country = cfg.TLS.CustomDetails.Country[0]
		}
		if len(cfg.TLS.CustomDetails.Province) > 0 {
			province = cfg.TLS.CustomDetails.Province[0]
		}
		if len(cfg.TLS.CustomDetails.Locality) > 0 {
			locality = cfg.TLS.CustomDetails.Locality[0]
		}
		if cfg.TLS.CustomDetails.CommonName != "" {
			commonName = cfg.TLS.CustomDetails.CommonName
		}
	}

	certConfig := &cert.CertConfig{
		CertFile:          cfg.TLS.CertFile,
		KeyFile:           cfg.TLS.KeyFile,
		CAFile:            cfg.TLS.CAFile,
		CAKeyFile:         cfg.TLS.CAKeyFile,
		CertDir:           cfg.TLS.CertDir,
		AutoGenerate:      cfg.TLS.AutoGenerate,
		ValidDays:         cfg.TLS.ValidDays,
		UpstreamCertSniff: cfg.TLS.UpstreamCertSniff,
		KeySize:           2048,
		Organization:      organization,
		Country:           country,
		Province:          province,
		Locality:          locality,
		CustomCommonName:  commonName,
	}

	return s.certManager.Initialize(certConfig)
}

// reloadCaptureManager reinitializes the capture manager with new config
func (s *Server) reloadCaptureManager(cfg *config.Config) error {
	// Create new capture manager
	newCaptureManager := capture.NewCaptureManager(cfg.Logging.CaptureDir, cfg.Logging.EnableDebug)
	if err := newCaptureManager.Initialize(); err != nil {
		return err
	}

	// Replace the old capture manager
	s.captureManager = newCaptureManager
	s.relayer.SetCaptureHandler(newCaptureManager)

	return nil
}

// reloadFilterManager reloads the filter manager with new rules
func (s *Server) reloadFilterManager(cfg *config.Config) error {
	// Create provider configs from legacy rules
	providerConfigs := map[string]interface{}{
		"domain": map[string]interface{}{
			"inspect_domains": cfg.Rules.InspectDomains,
			"bypass_domains":  cfg.Rules.BypassDomains,
			"enable_debug":    cfg.Logging.EnableDebug,
		},
		"ip": map[string]interface{}{
			"inspect_ips":  cfg.Rules.InspectIPs,
			"bypass_ips":   cfg.Rules.BypassIPs,
			"enable_debug": cfg.Logging.EnableDebug,
		},
	}

	return s.filterManager.ReloadProviders(providerConfigs)
}

// rulesChanged compares two LegacyRulesConfig structs for changes
func (s *Server) rulesChanged(old, newConfig config.LegacyRulesConfig) bool {
	return !s.stringSlicesEqual(old.InspectDomains, newConfig.InspectDomains) ||
		!s.stringSlicesEqual(old.InspectIPs, newConfig.InspectIPs) ||
		!s.stringSlicesEqual(old.BypassDomains, newConfig.BypassDomains) ||
		!s.stringSlicesEqual(old.BypassIPs, newConfig.BypassIPs)
}

// stringSlicesEqual compares two string slices for equality
func (s *Server) stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
