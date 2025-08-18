package proxy

import (
	"bytes"
	"context"
	"fmt"
	"io"
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
	"github.com/iamgaru/gander/internal/logging"
	"github.com/iamgaru/gander/internal/pool"
	"github.com/iamgaru/gander/internal/relay"
	tlsopt "github.com/iamgaru/gander/internal/tls"
	"github.com/iamgaru/gander/internal/worker"
	"github.com/iamgaru/gander/pkg/protocol"
)

// normalizeTarget ensures proper formatting for network addresses, especially IPv6
func normalizeTarget(target string) string {
	// Check if this looks like an IPv6 address with port
	if strings.Contains(target, ":") && !strings.HasPrefix(target, "[") {
		// Count colons to detect IPv6
		colonCount := strings.Count(target, ":")
		if colonCount > 1 {
			// Find the last colon (should be the port separator)
			lastColon := strings.LastIndex(target, ":")
			if lastColon > 0 && lastColon < len(target)-1 {
				host := target[:lastColon]
				port := target[lastColon+1:]
				
				// Validate that port is actually a number
				if _, err := strconv.Atoi(port); err == nil {
					// This looks like IPv6 with port, add brackets
					return "[" + host + "]:" + port
				}
			}
		}
	}
	// Return as-is if not IPv6 or already properly formatted
	return target
}

// Server represents the main proxy server
type Server struct {
	config        *config.Config
	filterManager *filter.Manager
	stats         *ProxyStats
	logger        *logging.Logger

	// Core components - Enhanced
	bufferPool       *pool.EnhancedBufferPool
	connectionPool   *pool.ConnectionPool
	workerPool       *worker.WorkerPool
	tlsSessionCache  *tlsopt.SessionCache
	certManager      cert.CertificateProvider
	certPreGenMgr    *cert.PreGenerationManager
	relayer          *relay.Relayer
	captureManager   *capture.CaptureManager

	// Runtime state
	logFile        *os.File
	shutdownCh     chan struct{}
	configReloadCh chan struct{}

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
		MaxSessions:         cfg.Performance.TLSSessionCache.MaxSessions,
		SessionTTL:          time.Duration(cfg.Performance.TLSSessionCache.SessionTTLHours) * time.Hour,
		TicketKeyRotation:   time.Duration(cfg.Performance.TLSSessionCache.TicketKeyRotationHr) * time.Hour,
		CleanupInterval:     5 * time.Minute,
		EnableDebug:         cfg.Logging.EnableDebug,
		EnableClientCache:   true,
		EnableServerCache:   true,
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
		Enabled:             cfg.Performance.CertPreGeneration.Enabled,
		WorkerCount:         cfg.Performance.CertPreGeneration.WorkerCount,
		QueueSize:           1000,
		PopularDomainCount:  cfg.Performance.CertPreGeneration.PopularDomainCount,
		FrequencyThreshold:  cfg.Performance.CertPreGeneration.FrequencyThreshold,
		PreGenInterval:      10 * time.Minute,
		DomainTTL:           24 * time.Hour,
		StaticDomains:       cfg.Performance.CertPreGeneration.StaticDomains,
		EnableFreqTracking:  cfg.Performance.CertPreGeneration.EnableFreqTracking,
		MaxConcurrentGens:   10,
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
	
	// Configure capture organization scheme from storage config
	captureConfig := capture.DefaultCaptureConfig()
	// Only set organization scheme if storage config exists and is not empty
	if cfg.Storage.OrganizationScheme != "" {
		captureConfig.OrganizationScheme = cfg.Storage.OrganizationScheme
	}
	captureManager.SetConfig(captureConfig)
	
	if err := captureManager.Initialize(); err != nil {
		return nil, err
	}
	relayer.SetCaptureHandler(captureManager)

	// Initialize structured logger
	logger, err := logging.NewLogger(cfg.Logging.ConsoleLevel, cfg.Logging.LogFile)
	if err != nil {
		return nil, err
	}

	// Configure log rotation if max file size is specified
	if cfg.Logging.MaxFileSize > 0 {
		logger.SetMaxFileSize(cfg.Logging.MaxFileSize)
	}

	// Initialize feature logger if configured
	if cfg.Logging.FeatureLogs != nil && cfg.Logging.FeatureLogs.Enabled {
		// Convert config to simple map
		logConfigs := make(map[string]bool)
		for name, config := range cfg.Logging.FeatureLogs.Logs {
			logConfigs[name] = config.Enabled
		}
		
		featureLogger, err := logging.NewFeatureLogger(
			cfg.Logging.FeatureLogs.Enabled,
			cfg.Logging.FeatureLogs.MaxFileSizeMB,
			"logs", // Same directory as main logs
			logConfigs,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize feature logger: %w", err)
		}
		
		logger.SetFeatureLogger(featureLogger)
		
		// Set up certificate logging callback
		certManager.SetCertLogger(func(action, domain string, duration time.Duration, status string, extra map[string]interface{}) {
			featureLogger.LogCertificate(action, domain, duration, status, extra)
		})
	}

	// Set up relay debug logging to use file-only verbose logging
	relayer.SetDebugLogger(logger.Verbose)

	server := &Server{
		config:           cfg,
		filterManager:    filterManager,
		stats:            stats,
		logger:           logger,
		bufferPool:       bufferPool,
		connectionPool:   connectionPool,
		workerPool:       workerPool,
		tlsSessionCache:  tlsSessionCache,
		certManager:      certManager,
		certPreGenMgr:    certPreGenMgr,
		relayer:          relayer,
		captureManager:   captureManager,
		logFile:          logFile,
		shutdownCh:       make(chan struct{}),
		configReloadCh:   make(chan struct{}, 1),
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
		s.logger.Info("TLS session cache enabled with %d max sessions", s.config.Performance.TLSSessionCache.MaxSessions)
	}

	// Start certificate pre-generation if enabled
	if s.config.Performance.CertPreGeneration.Enabled {
		if err := s.certPreGenMgr.Start(); err != nil {
			s.logger.Critical("Failed to start certificate pre-generation: %v", err)
		} else {
			s.logger.Info("Certificate pre-generation started")
		}
	}

	// Start HTTP listener
	httpListener, err := net.Listen("tcp", s.config.Proxy.ListenAddr)
	if err != nil {
		return err
	}
	s.httpListener = httpListener

	s.logger.Info("Proxy server listening on %s", s.config.Proxy.ListenAddr)

	// Start statistics reporting
	go s.reportStats()

	// Start connection cleanup routine
	go s.cleanupStaleConnections()

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
			s.logger.Verbose("Worker pool stop error: %v", err)
		}
	}

	// Stop certificate pre-generation
	if s.certPreGenMgr != nil && s.config.Performance.CertPreGeneration.Enabled {
		if err := s.certPreGenMgr.Stop(); err != nil {
			s.logger.Verbose("Certificate pre-generation stop error: %v", err)
		}
	}

	// Close connection pool
	if s.connectionPool != nil {
		if err := s.connectionPool.Close(); err != nil {
			s.logger.Verbose("Connection pool close error: %v", err)
		}
	}

	// Clear TLS session cache
	if s.tlsSessionCache != nil {
		cleared := s.tlsSessionCache.Clear()
		s.logger.Info("Cleared %d TLS sessions", cleared)
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

	s.logger.Shutdown("Proxy server stopped")
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
				s.logger.Verbose("Accept error: %v", err)
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
				s.logger.Verbose("Accept error: %v", err)
				continue
			}
		}

		// Submit connection to worker pool
		handler := &connectionHandler{server: s}
		if err := s.workerPool.SubmitConnection(conn, handler); err != nil {
			s.logger.Verbose("Failed to submit connection to worker pool: %v", err)
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
	
	// Set initial connection timeout
	clientConn.SetDeadline(time.Now().Add(30 * time.Second))
	
	// Create connection info with correlation ID
	correlationID := logging.GenerateCorrelationID()
	info := &relay.ConnectionInfo{
		ClientIP:      clientConn.RemoteAddr().String(),
		StartTime:     time.Now(),
		CorrelationID: correlationID,
	}

	// Create context with timeout for connection handling
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// Log connection initiation with structured logging
	s.logger.DebugStructured(correlationID, "New connection initiated",
		"client_ip", info.ClientIP,
	)

	// Monitor context cancellation
	go func() {
		<-ctx.Done()
		s.logger.DebugStructured(correlationID, "Connection context cancelled, closing connection",
			"client_ip", info.ClientIP,
		)
		clientConn.Close()
	}()

	// Read initial data to determine protocol using enhanced buffer pool
	pooledBuffer := s.bufferPool.NewPooledBuffer(pool.SmallBuffer)
	defer pooledBuffer.Release()
	
	buffer := pooledBuffer.Slice(1024)
	
	// Set read timeout for initial data
	clientConn.SetReadDeadline(time.Now().Add(30 * time.Second))
	n, err := clientConn.Read(buffer)
	if err != nil {
		s.logger.Verbose("Failed to read initial data: %v", err)
		return
	}

	// Clear deadline after successful read
	clientConn.SetDeadline(time.Time{})
	data := buffer[:n]

	// Detect protocol and extract connection information
	if protocol.IsHTTP2Connection(data) {
		s.logger.DebugStructured(correlationID, "Protocol detected",
			"protocol", "HTTP/2",
			"client_ip", info.ClientIP,
		)
		s.handleHTTP2Connection(clientConn, data, info)
	} else if protocol.IsWebSocketUpgrade(data) {
		s.logger.DebugStructured(correlationID, "Protocol detected",
			"protocol", "WebSocket",
			"client_ip", info.ClientIP,
		)
		s.handleWebSocketConnection(clientConn, data, info)
	} else if protocol.IsHTTPRequest(data) {
		s.logger.DebugStructured(correlationID, "Protocol detected",
			"protocol", "HTTP",
			"client_ip", info.ClientIP,
		)
		s.handleHTTPConnection(clientConn, data, info)
	} else if protocol.IsTLSHandshake(data) {
		// Check for HTTP/2 ALPN support
		alpnProtocols := protocol.ExtractALPN(data)
		if protocol.SupportsHTTP2(alpnProtocols) {
			s.logger.DebugStructured(correlationID, "Protocol detected",
				"protocol", "TLS with HTTP/2 ALPN",
				"client_ip", info.ClientIP,
				"alpn_protocols", fmt.Sprintf("%v", alpnProtocols),
			)
		} else {
			s.logger.DebugStructured(correlationID, "Protocol detected",
				"protocol", "TLS",
				"client_ip", info.ClientIP,
			)
		}
		s.handleTLSConnection(clientConn, data, info)
	} else {
		s.logger.DebugStructured(correlationID, "Protocol detected",
			"protocol", "Unknown",
			"client_ip", info.ClientIP,
		)
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
		s.logger.Verbose("Failed to extract host from HTTP request")
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
		s.logger.Verbose("Filter error: %v", err)
		return
	}

	switch decision.Result {
	case filter.FilterBlock:
		s.logger.InfoStructured(info.CorrelationID, "Connection blocked by filter",
			"client_ip", info.ClientIP,
			"domain", info.Domain,
			"reason", decision.Reason,
		)
		// Log to filtering.log
		if featureLogger := s.logger.GetFeatureLogger(); featureLogger != nil {
			featureLogger.LogFiltering(info.CorrelationID, info.Domain, info.ClientIP, "blocked", "domain_inspection", decision.Reason)
		}
		return
	case filter.FilterBypass:
		s.logger.DebugStructured(info.CorrelationID, "Connection bypassed",
			"domain", info.Domain,
			"reason", decision.Reason,
		)
		// Log to filtering.log
		if featureLogger := s.logger.GetFeatureLogger(); featureLogger != nil {
			featureLogger.LogFiltering(info.CorrelationID, info.Domain, info.ClientIP, "allowed", "domain_inspection", decision.Reason)
		}
		_ = s.relayer.HandleHTTPRelay(clientConn, data, info, false)
	case filter.FilterInspect, filter.FilterCapture:
		s.stats.IncrementInspected()
		s.logger.DebugStructured(info.CorrelationID, "Connection marked for inspection",
			"domain", info.Domain,
			"action", decision.Result.String(),
			"reason", decision.Reason,
		)
		// Log to filtering.log
		if featureLogger := s.logger.GetFeatureLogger(); featureLogger != nil {
			featureLogger.LogFiltering(info.CorrelationID, info.Domain, info.ClientIP, "allowed", "domain_inspection", decision.Reason)
		}
		_ = s.relayer.HandleHTTPRelay(clientConn, data, info, true)
	default:
		s.logger.DebugStructured(info.CorrelationID, "Connection using default handling",
			"domain", info.Domain,
		)
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
		s.logger.DebugStructured(info.CorrelationID, "Failed to extract SNI from TLS handshake",
			"client_ip", info.ClientIP,
		)
		return
	}

	s.logger.DebugStructured(info.CorrelationID, "SNI extracted from TLS handshake",
		"domain", sni,
		"client_ip", info.ClientIP,
	)

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
		s.logger.Verbose("Filter error: %v", err)
		return
	}

	switch decision.Result {
	case filter.FilterBlock:
		s.logger.InfoStructured(info.CorrelationID, "HTTPS connection blocked by filter",
			"client_ip", info.ClientIP,
			"domain", info.Domain,
			"reason", decision.Reason,
		)
		// Log to filtering.log
		if featureLogger := s.logger.GetFeatureLogger(); featureLogger != nil {
			featureLogger.LogFiltering(info.CorrelationID, info.Domain, info.ClientIP, "blocked", "sni_sniff", decision.Reason)
		}
		return
	case filter.FilterBypass:
		s.logger.DebugStructured(info.CorrelationID, "HTTPS connection bypassed",
			"domain", info.Domain,
			"reason", decision.Reason,
		)
		// Log to filtering.log
		if featureLogger := s.logger.GetFeatureLogger(); featureLogger != nil {
			featureLogger.LogFiltering(info.CorrelationID, info.Domain, info.ClientIP, "allowed", "sni_sniff", decision.Reason)
		}
		_ = s.relayer.HandleTransparentRelay(clientConn, data, info)
	case filter.FilterInspect, filter.FilterCapture:
		s.stats.IncrementInspected()
		s.logger.DebugStructured(info.CorrelationID, "HTTPS connection marked for inspection",
			"domain", info.Domain,
			"action", decision.Result.String(),
			"reason", decision.Reason,
		)
		// Log to filtering.log
		if featureLogger := s.logger.GetFeatureLogger(); featureLogger != nil {
			featureLogger.LogFiltering(info.CorrelationID, info.Domain, info.ClientIP, "allowed", "sni_sniff", decision.Reason)
		}
		// Filter manager already decided - perform HTTPS inspection
		_ = s.relayer.HandleHTTPSInspection(clientConn, info.ServerAddr, info)
	default:
		s.logger.DebugStructured(info.CorrelationID, "HTTPS connection using transparent relay",
			"domain", info.Domain,
		)
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
	s.logger.Verbose("Unknown protocol from %s, closing connection", info.ClientIP)
}

// handleCONNECTRequest handles HTTP CONNECT requests for HTTPS proxy tunneling
func (s *Server) handleCONNECTRequest(clientConn net.Conn, data []byte, info *relay.ConnectionInfo) {
	// Parse CONNECT request
	lines := bytes.Split(data, []byte("\r\n"))
	if len(lines) == 0 {
		s.logger.Debug("Invalid CONNECT request")
		return
	}

	requestLine := string(lines[0])
	parts := strings.Fields(requestLine)
	if len(parts) < 2 {
		s.logger.Debug("Invalid CONNECT request line: %s", requestLine)
		return
	}

	target := normalizeTarget(parts[1]) // e.g., "mail.google.com:443" or "[::1]:443"

	// Extract domain without port for filtering
	host := target
	if strings.HasPrefix(target, "[") {
		// IPv6 case: [2001:db8::1]:443
		if closeBracket := strings.Index(target, "]"); closeBracket > 0 {
			host = target[1:closeBracket] // Extract IPv6 address without brackets
		}
	} else if colonIdx := strings.LastIndex(target, ":"); colonIdx != -1 {
		// IPv4 case: example.com:443
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
		s.logger.Verbose("Filter error: %v", err)
		return
	}

	switch decision.Result {
	case filter.FilterBlock:
		s.logger.Info("Blocked HTTPS connection: %s -> %s", info.ClientIP, info.Domain)
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
func (s *Server) handleTransparentTunnel(clientConn net.Conn, target string, info *relay.ConnectionInfo) {
	s.logger.DebugStructured(info.CorrelationID, "Establishing transparent tunnel",
		"target", target,
		"client_ip", info.ClientIP,
	)

	// Connect to target server with timeout
	serverConn, err := net.DialTimeout("tcp", target, 30*time.Second)
	if err != nil {
		s.logger.Verbose("Failed to connect to %s: %v", target, err)
		_, _ = clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"))
		return
	}

	// Send 200 Connection established
	_, err = clientConn.Write([]byte("HTTP/1.1 200 Connection established\r\nContent-Length: 0\r\n\r\n"))
	if err != nil {
		s.logger.Verbose("Failed to send CONNECT response: %v", err)
		serverConn.Close()
		return
	}

	s.logger.DebugStructured(info.CorrelationID, "CONNECT tunnel established",
		"target", target,
		"client_ip", info.ClientIP,
	)

	// Start bidirectional relay with proper error handling
	done := make(chan struct{}, 2)
	
	// Copy client -> server
	go func() {
		defer serverConn.Close()
		s.copyDataWithInfo(serverConn, clientConn, "client->server", info)
		done <- struct{}{}
	}()
	
	// Copy server -> client
	go func() {
		defer clientConn.Close()
		s.copyDataWithInfo(clientConn, serverConn, "server->client", info)
		done <- struct{}{}
	}()
	
	// Wait for one direction to complete (connection closed)
	<-done
}

// handleMITMTunnel establishes a MITM tunnel with certificate interception
func (s *Server) handleMITMTunnel(clientConn net.Conn, target string, info *relay.ConnectionInfo) {
	// Send 200 Connection established to make client think tunnel is ready
	_, err := clientConn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
	if err != nil {
		s.logger.Verbose("Failed to send CONNECT response: %v", err)
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
		s.logger.Verbose("Error copying data (%s): %v", direction, err)
	}
}

// copyDataWithInfo copies data between connections and tracks bytes for connection info
func (s *Server) copyDataWithInfo(dst, src net.Conn, direction string, info *relay.ConnectionInfo) {
	pooledBuffer := s.bufferPool.NewPooledBuffer(pool.LargeBuffer)
	defer pooledBuffer.Release()

	buffer := pooledBuffer.Bytes()
	for {
		// Set read timeout to prevent hanging connections
		src.SetReadDeadline(time.Now().Add(5 * time.Minute))
		n, err := src.Read(buffer)
		if err != nil {
			if !strings.Contains(err.Error(), "use of closed network connection") &&
			   !strings.Contains(err.Error(), "timeout") {
				s.logger.Verbose("Error reading data (%s): %v", direction, err)
			}
			break
		}

		if n == 0 {
			break
		}

		// Set write timeout
		dst.SetWriteDeadline(time.Now().Add(30 * time.Second))
		written, err := dst.Write(buffer[:n])
		if err != nil {
			if !strings.Contains(err.Error(), "use of closed network connection") {
				s.logger.Verbose("Error writing data (%s): %v", direction, err)
			}
			break
		}

		// Update connection statistics
		if strings.Contains(direction, "client->server") {
			info.BytesWritten += int64(written)
		} else {
			info.BytesRead += int64(written)
		}
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

// handleHTTP2Connection handles HTTP/2 connections
func (s *Server) handleHTTP2Connection(clientConn net.Conn, data []byte, info *relay.ConnectionInfo) {
	info.Protocol = "HTTP/2"
	
	s.logger.DebugStructured(info.CorrelationID, "HTTP/2 connection detected",
		"client_ip", info.ClientIP,
	)
	
	// For now, treat HTTP/2 as transparent relay until full HTTP/2 proxy support is implemented
	// Extract target from the connection preface or fall back to transparent handling
	_ = s.relayer.HandleTransparentRelay(clientConn, data, info)
	s.logConnection(info)
}

// handleWebSocketConnection handles WebSocket upgrade requests
func (s *Server) handleWebSocketConnection(clientConn net.Conn, data []byte, info *relay.ConnectionInfo) {
	// Extract host for WebSocket connections
	host := protocol.ExtractHTTPHost(data)
	if host == "" {
		s.logger.Verbose("Failed to extract host from WebSocket request")
		return
	}

	info.Domain = host
	info.ServerAddr = host + ":443" // Most WebSockets use HTTPS
	info.Protocol = "WebSocket"

	s.logger.DebugStructured(info.CorrelationID, "WebSocket upgrade request",
		"domain", info.Domain,
		"client_ip", info.ClientIP,
	)

	// Apply filters
	ctx := context.Background()
	filterCtx := &filter.FilterContext{
		ClientIP:   net.ParseIP(info.ClientIP),
		ServerAddr: info.ServerAddr,
		Domain:     info.Domain,
		Protocol:   info.Protocol,
		IsHTTPS:    true, // Most WebSocket upgrades happen over WSS
	}

	decision, err := s.filterManager.ProcessPacket(ctx, filterCtx)
	if err != nil {
		s.logger.Verbose("Filter error: %v", err)
		return
	}

	switch decision.Result {
	case filter.FilterBlock:
		s.logger.InfoStructured(info.CorrelationID, "WebSocket connection blocked by filter",
			"client_ip", info.ClientIP,
			"domain", info.Domain,
			"reason", decision.Reason,
		)
		return
	case filter.FilterBypass:
		s.logger.DebugStructured(info.CorrelationID, "WebSocket connection bypassed",
			"domain", info.Domain,
			"reason", decision.Reason,
		)
		_ = s.handleWebSocketUpgrade(clientConn, data, info, false)
	case filter.FilterInspect, filter.FilterCapture:
		s.stats.IncrementInspected()
		s.logger.DebugStructured(info.CorrelationID, "WebSocket connection marked for inspection",
			"domain", info.Domain,
			"action", decision.Result.String(),
			"reason", decision.Reason,
		)
		_ = s.handleWebSocketUpgrade(clientConn, data, info, true)
	default:
		_ = s.handleWebSocketUpgrade(clientConn, data, info, false)
	}

	s.logConnection(info)
}

// handleWebSocketUpgrade handles the WebSocket upgrade process
func (s *Server) handleWebSocketUpgrade(clientConn net.Conn, data []byte, info *relay.ConnectionInfo, inspect bool) error {
	// For now, handle WebSocket upgrades as HTTP requests
	// Full WebSocket inspection would require implementing the WebSocket protocol
	if inspect {
		return s.relayer.HandleHTTPRelay(clientConn, data, info, true)
	}
	return s.relayer.HandleHTTPRelay(clientConn, data, info, false)
}

// logConnection logs connection information using structured logging
func (s *Server) logConnection(info *relay.ConnectionInfo) {
	duration := time.Since(info.StartTime)
	isInspected := "false"
	if info.BytesRead > 0 || info.BytesWritten > 0 {
		isInspected = "true"
	}

	// Use structured logging with correlation ID
	s.logger.InfoStructured(info.CorrelationID, "Connection completed",
		"client_ip", info.ClientIP,
		"server_addr", info.ServerAddr,
		"domain", info.Domain,
		"protocol", info.Protocol,
		"duration_ms", strconv.FormatInt(duration.Milliseconds(), 10),
		"bytes_read", strconv.FormatInt(info.BytesRead, 10),
		"bytes_written", strconv.FormatInt(info.BytesWritten, 10),
		"inspected", isInspected,
	)
	
	// Log to performance.log if duration is significant or slow (only if feature logging enabled)
	if featureLogger := s.logger.GetFeatureLogger(); featureLogger != nil {
		// Quick check: only do expensive work if performance logging might actually happen
		durationMs := duration.Milliseconds()
		if durationMs > 100 { // Log requests taking longer than 100ms
			extra := map[string]interface{}{
				"domain":    info.Domain,
				"client_ip": info.ClientIP,
				"bytes_read": info.BytesRead,
				"bytes_written": info.BytesWritten,
				"threshold": "100ms",
			}
			featureLogger.LogPerformance("request_duration", fmt.Sprintf("%dms", durationMs), extra)
		}
	}
}

// reportStats periodically reports statistics
func (s *Server) reportStats() {
	// Parse initial status interval from config
	statusInterval, err := time.ParseDuration(s.config.Logging.StatusInterval)
	if err != nil {
		s.logger.Critical("Invalid status interval '%s', using default 30s: %v", s.config.Logging.StatusInterval, err)
		statusInterval = 30 * time.Second
	}

	ticker := time.NewTicker(statusInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			proxyStats := s.stats.GetStats()
			captureStats := s.captureManager.GetStats()
			certStats := s.certManager.GetStats()

			// Enhanced statistics reporting - only to file (verbose)
			s.logger.Verbose("Proxy Stats: %d total, %d active, %d inspected | Capture: %d requests, %d responses, %d pairs | Certs: %d generated, %d cached",
				proxyStats.TotalConnections,
				proxyStats.ActiveConnections,
				proxyStats.InspectedConnections,
				captureStats.RequestsCaptured,
				captureStats.ResponsesCaptured,
				captureStats.PairsCaptured,
				certStats.GeneratedCerts,
				certStats.CachedCerts,
			)
			
			// Log key performance metrics to performance.log
			if featureLogger := s.logger.GetFeatureLogger(); featureLogger != nil {
				featureLogger.LogPerformance("active_connections", proxyStats.ActiveConnections, 
					map[string]interface{}{"component": "proxy"})
				featureLogger.LogPerformance("cert_cache_size", certStats.CachedCerts, 
					map[string]interface{}{"component": "cert_cache"})
			}

			// Connection pool stats - file only (verbose)
			if s.connectionPool != nil {
				poolStats := s.connectionPool.GetStats()
				s.logger.Verbose("Connection Pool: %d pools, %d total conns, %d active, %d idle | Hits: %d, Misses: %d, Hit Rate: %.1f%%",
					poolStats.TotalPools,
					poolStats.TotalConnections,
					poolStats.ActiveConnections,
					poolStats.IdleConnections,
					poolStats.PoolHits,
					poolStats.PoolMisses,
					float64(poolStats.PoolHits)*100/float64(poolStats.PoolHits+poolStats.PoolMisses+1),
				)
				
				// Log connection pool metrics to performance.log
				if featureLogger := s.logger.GetFeatureLogger(); featureLogger != nil {
					featureLogger.LogPerformance("connection_pool_size", poolStats.TotalConnections, 
						map[string]interface{}{"component": "connection_pool", "max_size": s.config.Performance.ConnectionPool.MaxPoolSize})
				}
			}

			// Worker pool stats - file only (verbose)
			if s.workerPool != nil && s.config.Performance.WorkerPool.Enabled {
				workerStats := s.workerPool.GetStats()
				s.logger.Verbose("Worker Pool: %d active, %d idle, %d queued | Processed: %d, Failed: %d, Avg Latency: %dms",
					workerStats.ActiveWorkers,
					workerStats.IdleWorkers,
					workerStats.CurrentQueueLen,
					workerStats.ProcessedJobs,
					workerStats.FailedJobs,
					workerStats.AverageLatency,
				)
			}

			// TLS session cache stats - file only (verbose)
			if s.tlsSessionCache != nil && s.config.Performance.TLSSessionCache.Enabled {
				sessionStats := s.tlsSessionCache.GetStats()
				s.logger.Verbose("TLS Sessions: %d active, %d hits, %d misses | Resumption Rate: %.1f%%",
					sessionStats.ActiveSessions,
					sessionStats.SessionHits,
					sessionStats.SessionMisses,
					sessionStats.ResumptionRate*100,
				)
			}

			// Certificate pre-generation stats - file only (verbose)
			if s.certPreGenMgr != nil && s.config.Performance.CertPreGeneration.Enabled {
				preGenStats := s.certPreGenMgr.GetStats()
				s.logger.Verbose("Cert PreGen: %d generated, %d queued, %d popular domains | Utilization: %.1f%%",
					preGenStats.TotalPreGenerated,
					preGenStats.QueuedDomains,
					preGenStats.PopularDomainCount,
					preGenStats.WorkerUtilization*100,
				)
			}

			// Buffer pool efficiency - file only (verbose)
			if s.bufferPool != nil {
				efficiency := s.bufferPool.GetEfficiency()
				if overall, ok := efficiency["overall_reuse_rate"]; ok {
					s.logger.Verbose("Buffer Pool: %.1f%% reuse rate", overall*100)
				}
			}

		case <-s.configReloadCh:
			// Config changed, update ticker interval
			newInterval, err := time.ParseDuration(s.config.Logging.StatusInterval)
			if err != nil {
				s.logger.Critical("Invalid status interval '%s', keeping current: %v", s.config.Logging.StatusInterval, err)
				continue
			}
			if newInterval != statusInterval {
				statusInterval = newInterval
				ticker.Stop()
				ticker = time.NewTicker(statusInterval)
				s.logger.Info("Status interval updated to %s", statusInterval)
			}

		case <-s.shutdownCh:
			return
		}
	}
}

// cleanupStaleConnections periodically cleans up stale connections and resources
func (s *Server) cleanupStaleConnections() {
	ticker := time.NewTicker(2 * time.Minute) // Run every 2 minutes
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Log resource utilization for monitoring
			if s.connectionPool != nil {
				stats := s.connectionPool.GetStats()
				if stats.IdleConnections > 50 {
					s.logger.Verbose("High number of idle connections: %d", stats.IdleConnections)
				}
			}

			// Cleanup buffer pool if it has efficiency monitoring
			if s.bufferPool != nil {
				efficiency := s.bufferPool.GetEfficiency()
				if overallRate, ok := efficiency["overall_reuse_rate"]; ok && overallRate < 0.5 {
					s.logger.Verbose("Buffer pool efficiency low: %.1f%%", overallRate*100)
				}
			}

			// Log TLS session cache stats
			if s.tlsSessionCache != nil && s.config.Performance.TLSSessionCache.Enabled {
				stats := s.tlsSessionCache.GetStats()
				s.logger.Verbose("TLS cache: %d active sessions, %.1f%% hit rate",
					stats.ActiveSessions, stats.ResumptionRate*100)
			}

			// Log certificate pre-generation stats  
			if s.certPreGenMgr != nil && s.config.Performance.CertPreGeneration.Enabled {
				stats := s.certPreGenMgr.GetStats()
				s.logger.Verbose("Cert pre-gen: %d generated, %d queued",
					stats.TotalPreGenerated, stats.QueuedDomains)
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
	s.logger.Config("Reloading server configuration...")

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
			s.logger.Critical("Failed to reload filter manager: %v", err)
			// Revert config on failure
			s.config = oldConfig
			return err
		}
	}

	// Update certificate manager if TLS settings changed
	if oldConfig.TLS != newConfig.TLS {
		if err := s.reloadCertificateManager(newConfig); err != nil {
			s.logger.Critical("Failed to reload certificate manager: %v", err)
			// Revert config on failure
			s.config = oldConfig
			return err
		}
	}

	// Update capture manager if logging settings changed
	if oldConfig.Logging.CaptureDir != newConfig.Logging.CaptureDir {
		if err := s.reloadCaptureManager(newConfig); err != nil {
			s.logger.Critical("Failed to reload capture manager: %v", err)
			// Revert config on failure
			s.config = oldConfig
			return err
		}
	}

	// Signal the stats reporter to update its interval
	select {
	case s.configReloadCh <- struct{}{}:
	default:
		// Channel buffer full, skip (non-blocking)
	}

	s.logger.Config("Server configuration reloaded successfully")
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
	
	// Configure capture organization scheme from storage config
	captureConfig := capture.DefaultCaptureConfig()
	// Only set organization scheme if storage config exists and is not empty
	if cfg.Storage.OrganizationScheme != "" {
		captureConfig.OrganizationScheme = cfg.Storage.OrganizationScheme
	}
	newCaptureManager.SetConfig(captureConfig)
	
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
