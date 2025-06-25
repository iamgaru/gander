package proxy

import (
	"context"
	"log"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/iamgaru/gander/internal/capture"
	"github.com/iamgaru/gander/internal/cert"
	"github.com/iamgaru/gander/internal/config"
	"github.com/iamgaru/gander/internal/filter"
	"github.com/iamgaru/gander/internal/relay"
	"github.com/iamgaru/gander/pkg/protocol"
)

// Server represents the main proxy server
type Server struct {
	config        *config.Config
	filterManager *filter.Manager
	stats         *ProxyStats

	// Core components
	bufferPool     *relay.BufferPool
	certManager    cert.CertificateProvider
	relayer        *relay.Relayer
	captureManager *capture.CaptureManager

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

	// Create components
	bufferPool := relay.NewBufferPool(cfg.Proxy.BufferSize)
	stats := NewProxyStats()

	// Initialize certificate manager
	certManager := cert.NewCertificateManager(cfg.Logging.EnableDebug)
	if cfg.TLS.AutoGenerate {
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
			Organization:      "Gander Proxy",
			Country:           "US",
			Province:          "CA",
			Locality:          "San Francisco",
		}

		if err := certManager.Initialize(certConfig); err != nil {
			return nil, err
		}
	}

	// Initialize relayer
	relayer := relay.NewRelayer(
		bufferPool,
		time.Duration(cfg.Proxy.ReadTimeout)*time.Second,
		time.Duration(cfg.Proxy.WriteTimeout)*time.Second,
		cfg.Logging.EnableDebug,
	)
	relayer.SetCertificateManager(certManager)

	// Initialize capture manager
	captureManager := capture.NewCaptureManager(cfg.Logging.CaptureDir, cfg.Logging.EnableDebug)
	if err := captureManager.Initialize(); err != nil {
		return nil, err
	}
	relayer.SetCaptureHandler(captureManager)

	server := &Server{
		config:         cfg,
		filterManager:  filterManager,
		stats:          stats,
		bufferPool:     bufferPool,
		certManager:    certManager,
		relayer:        relayer,
		captureManager: captureManager,
		logFile:        logFile,
		shutdownCh:     make(chan struct{}),
	}

	return server, nil
}

// Start starts the proxy server
func (s *Server) Start() error {
	// Start HTTP listener
	httpListener, err := net.Listen("tcp", s.config.Proxy.ListenAddr)
	if err != nil {
		return err
	}
	s.httpListener = httpListener

	log.Printf("Proxy server listening on %s", s.config.Proxy.ListenAddr)

	// Start statistics reporting
	go s.reportStats()

	// Accept connections
	go s.acceptConnections(httpListener)

	return nil
}

// Stop stops the proxy server
func (s *Server) Stop() error {
	close(s.shutdownCh)

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
		s.certManager.Shutdown()
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

	// Read initial data to determine protocol
	buffer := make([]byte, 1024)
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
	// Extract host from HTTP request
	host := protocol.ExtractHTTPHost(data)
	if host == "" {
		log.Printf("Failed to extract host from HTTP request")
		return
	}

	info.Domain = host
	info.ServerAddr = host + ":80"
	info.Protocol = "HTTP"

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
		s.relayer.HandleHTTPRelay(clientConn, data, info, false)
	case filter.FilterInspect, filter.FilterCapture:
		s.stats.IncrementInspected()
		s.relayer.HandleHTTPRelay(clientConn, data, info, true)
	default:
		s.relayer.HandleHTTPRelay(clientConn, data, info, false)
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
		s.relayer.HandleTransparentRelay(clientConn, data, info)
	case filter.FilterInspect, filter.FilterCapture:
		s.stats.IncrementInspected()
		// Only perform HTTPS inspection if domain is in inspect list
		if s.shouldInspectDomain(info.Domain) {
			s.relayer.HandleHTTPSInspection(clientConn, info.ServerAddr, info)
		} else {
			s.relayer.HandleTransparentRelay(clientConn, data, info)
		}
	default:
		s.relayer.HandleTransparentRelay(clientConn, data, info)
	}

	// Log connection
	s.logConnection(info)
}

// handleUnknownConnection handles unknown protocol connections
func (s *Server) handleUnknownConnection(clientConn net.Conn, data []byte, info *relay.ConnectionInfo) {
	info.Protocol = "UNKNOWN"

	// For unknown protocols, try to extract destination from transparent proxy
	// This is a simplified approach - real implementation would use SO_ORIGINAL_DST
	log.Printf("Unknown protocol from %s, closing connection", info.ClientIP)
}

// shouldInspectDomain checks if a domain should have HTTPS inspection
func (s *Server) shouldInspectDomain(domain string) bool {
	// Check if domain is in the inspect domains list (domain-driven certificate generation)
	for _, inspectDomain := range s.config.Rules.InspectDomains {
		if s.matchesDomain(domain, inspectDomain) {
			return true
		}
	}
	return false
}

// matchesDomain checks if a domain matches a pattern (supporting wildcards)
func (s *Server) matchesDomain(domain, pattern string) bool {
	if pattern == domain {
		return true
	}

	// Handle wildcard patterns
	if len(pattern) > 0 && pattern[0] == '*' && len(pattern) > 1 {
		suffix := pattern[1:] // Remove the '*'
		return len(domain) >= len(suffix) && domain[len(domain)-len(suffix):] == suffix
	}

	return false
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
		s.logFile.WriteString(logEntry + "\n")
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

	return map[string]interface{}{
		"proxy":   proxyStats,
		"capture": captureStats,
		"certs":   certStats,
	}
}
