package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Configuration structure
type Config struct {
	Proxy struct {
		ListenAddr   string `json:"listen_addr"`
		Transparent  bool   `json:"transparent"`
		ExplicitPort int    `json:"explicit_port"`
		BufferSize   int    `json:"buffer_size"`
		ReadTimeout  int    `json:"read_timeout_seconds"`
		WriteTimeout int    `json:"write_timeout_seconds"`
	} `json:"proxy"`

	Logging struct {
		LogFile     string `json:"log_file"`
		CaptureDir  string `json:"capture_dir"`
		MaxFileSize int64  `json:"max_file_size_mb"`
		EnableDebug bool   `json:"enable_debug"`
	} `json:"logging"`

	Rules struct {
		InspectDomains []string `json:"inspect_domains"`
		InspectIPs     []string `json:"inspect_source_ips"`
		BypassDomains  []string `json:"bypass_domains"`
		BypassIPs      []string `json:"bypass_source_ips"`
	} `json:"rules"`

	TLS struct {
		CertFile          string `json:"cert_file"`
		KeyFile           string `json:"key_file"`
		CAFile            string `json:"ca_file"`
		CAKeyFile         string `json:"ca_key_file"`
		CertDir           string `json:"cert_dir"`
		AutoGenerate      bool   `json:"auto_generate"`
		ValidDays         int    `json:"valid_days"`
		UpstreamCertSniff bool   `json:"upstream_cert_sniff"`
	} `json:"tls"`
}

// Proxy server structure
type ProxyServer struct {
	config         *Config
	inspectDomains map[string]bool
	inspectIPs     map[string]bool
	bypassDomains  map[string]bool
	bypassIPs      map[string]bool
	logFile        *os.File
	bufferPool     *sync.Pool
	stats          *ProxyStats
	mutex          sync.RWMutex
	caCert         *x509.Certificate
	caKey          *rsa.PrivateKey
	certCache      map[string]*tls.Certificate
	certMutex      sync.RWMutex
}

// Connection statistics
type ProxyStats struct {
	TotalConnections     int64 `json:"total_connections"`
	ActiveConnections    int64 `json:"active_connections"`
	BytesTransferred     int64 `json:"bytes_transferred"`
	InspectedConnections int64 `json:"inspected_connections"`
	CapturedRequests     int64 `json:"captured_requests"`
}

// Connection metadata
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

// HTTPCapture represents a captured HTTP request/response
type HTTPCapture struct {
	Timestamp   time.Time         `json:"timestamp"`
	ClientIP    string            `json:"client_ip"`
	Domain      string            `json:"domain"`
	Method      string            `json:"method"`
	URL         string            `json:"url"`
	Path        string            `json:"path"`
	Query       string            `json:"query,omitempty"`
	HTTPVersion string            `json:"http_version"`
	Headers     map[string]string `json:"headers"`
	Body        string            `json:"body,omitempty"`
	BodySize    int               `json:"body_size"`
	ContentType string            `json:"content_type,omitempty"`
	UserAgent   string            `json:"user_agent,omitempty"`
	Referer     string            `json:"referer,omitempty"`
	Response    *HTTPResponse     `json:"response,omitempty"`
}

type HTTPResponse struct {
	StatusCode int               `json:"status_code"`
	Headers    map[string]string `json:"headers"`
	Body       string            `json:"body,omitempty"`
	BodySize   int               `json:"body_size"`
}

// Load configuration from file
func loadConfig(filename string) (*Config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var config Config
	err = json.Unmarshal(data, &config)
	if err != nil {
		return nil, err
	}

	// Set defaults
	if config.Proxy.BufferSize == 0 {
		config.Proxy.BufferSize = 32768
	}
	if config.Proxy.ReadTimeout == 0 {
		config.Proxy.ReadTimeout = 30
	}
	if config.Proxy.WriteTimeout == 0 {
		config.Proxy.WriteTimeout = 30
	}
	if config.Logging.MaxFileSize == 0 {
		config.Logging.MaxFileSize = 100
	}
	if config.TLS.ValidDays == 0 {
		config.TLS.ValidDays = 365
	}
	if config.TLS.CertDir == "" {
		config.TLS.CertDir = "certs"
	}

	return &config, nil
}

// Create new proxy server
func NewProxyServer(config *Config) (*ProxyServer, error) {
	// Open log file
	logFile, err := os.OpenFile(config.Logging.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, err
	}

	// Create capture directory
	if err := os.MkdirAll(config.Logging.CaptureDir, 0755); err != nil {
		return nil, err
	}

	// Create lookup maps for fast access
	inspectDomains := make(map[string]bool)
	for _, domain := range config.Rules.InspectDomains {
		inspectDomains[strings.ToLower(domain)] = true
	}

	inspectIPs := make(map[string]bool)
	for _, ip := range config.Rules.InspectIPs {
		inspectIPs[ip] = true
	}

	bypassDomains := make(map[string]bool)
	for _, domain := range config.Rules.BypassDomains {
		bypassDomains[strings.ToLower(domain)] = true
	}

	bypassIPs := make(map[string]bool)
	for _, ip := range config.Rules.BypassIPs {
		bypassIPs[ip] = true
	}

	// Buffer pool for performance
	bufferPool := &sync.Pool{
		New: func() interface{} {
			buf := make([]byte, config.Proxy.BufferSize)
			return &buf
		},
	}

	ps := &ProxyServer{
		config:         config,
		inspectDomains: inspectDomains,
		inspectIPs:     inspectIPs,
		bypassDomains:  bypassDomains,
		bypassIPs:      bypassIPs,
		logFile:        logFile,
		bufferPool:     bufferPool,
		stats:          &ProxyStats{},
		certCache:      make(map[string]*tls.Certificate),
	}

	// Initialize CA certificate
	if err := ps.loadOrGenerateCA(); err != nil {
		return nil, fmt.Errorf("failed to initialize CA: %v", err)
	}

	return ps, nil
}

// Extract SNI from TLS ClientHello
func extractSNI(data []byte) string {
	if len(data) < 43 {
		return ""
	}

	// Check for TLS handshake
	if data[0] != 0x16 || data[5] != 0x01 {
		return ""
	}

	// Parse TLS extensions to find SNI
	pos := 43
	if pos >= len(data) {
		return ""
	}

	// Skip session ID
	sessionIDLen := int(data[pos])
	pos += 1 + sessionIDLen
	if pos+2 >= len(data) {
		return ""
	}

	// Skip cipher suites
	cipherSuitesLen := int(data[pos])<<8 | int(data[pos+1])
	pos += 2 + cipherSuitesLen
	if pos+1 >= len(data) {
		return ""
	}

	// Skip compression methods
	compressionLen := int(data[pos])
	pos += 1 + compressionLen
	if pos+2 >= len(data) {
		return ""
	}

	// Parse extensions
	extensionsLen := int(data[pos])<<8 | int(data[pos+1])
	pos += 2
	end := pos + extensionsLen

	for pos+4 < end && pos+4 < len(data) {
		extType := int(data[pos])<<8 | int(data[pos+1])
		extLen := int(data[pos+2])<<8 | int(data[pos+3])
		pos += 4

		if extType == 0 && pos+5 < len(data) { // SNI extension
			nameLen := int(data[pos+3])<<8 | int(data[pos+4])
			if pos+5+nameLen <= len(data) {
				return string(data[pos+5 : pos+5+nameLen])
			}
			break
		}
		pos += extLen
	}

	return ""
}

// Extract HTTP host header
func extractHTTPHost(data []byte) string {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(strings.ToLower(line), "host: ") {
			return strings.TrimSpace(line[6:])
		}
	}
	return ""
}

// Determine if connection should be inspected
func (ps *ProxyServer) shouldInspect(clientIP, domain string) bool {
	ps.mutex.RLock()
	defer ps.mutex.RUnlock()

	// Check bypass rules first
	if ps.bypassIPs[clientIP] || ps.bypassDomains[strings.ToLower(domain)] {
		return false
	}

	// Check inspect rules
	return ps.inspectIPs[clientIP] || ps.inspectDomains[strings.ToLower(domain)]
}

// Log connection info
func (ps *ProxyServer) logConnection(info *ConnectionInfo) {
	duration := time.Since(info.StartTime)
	logLine := fmt.Sprintf("[%s] %s -> %s (%s) | %s | %d/%d bytes | %v | inspected=%t captured=%t\n",
		time.Now().Format("2006-01-02 15:04:05.000"),
		info.ClientIP,
		info.ServerAddr,
		info.Domain,
		duration,
		info.BytesRead,
		info.BytesWrite,
		info.Protocol,
		info.Inspected,
		info.Captured)

	if _, err := ps.logFile.WriteString(logLine); err != nil {
		log.Printf("Failed to write to log file: %v", err)
	}
	if err := ps.logFile.Sync(); err != nil {
		log.Printf("Failed to sync log file: %v", err)
	}
}

// Parse HTTP request with enhanced details
func parseHTTPRequest(data []byte) (*HTTPCapture, error) {
	// Find the end of headers (double CRLF)
	headerEndIndex := bytes.Index(data, []byte("\r\n\r\n"))
	if headerEndIndex == -1 {
		// If no double CRLF found, treat entire data as headers (incomplete request)
		headerEndIndex = len(data)
	}

	headerData := data[:headerEndIndex]
	reader := bufio.NewReader(bytes.NewReader(headerData))

	// Parse request line
	requestLine, _, err := reader.ReadLine()
	if err != nil {
		return nil, err
	}

	parts := strings.Fields(string(requestLine))
	if len(parts) < 3 {
		return nil, fmt.Errorf("invalid HTTP request line")
	}

	// Parse URL and query parameters
	fullURL := parts[1]
	var path, query string
	if queryIndex := strings.Index(fullURL, "?"); queryIndex != -1 {
		path = fullURL[:queryIndex]
		query = fullURL[queryIndex+1:]
	} else {
		path = fullURL
	}

	capture := &HTTPCapture{
		Timestamp:   time.Now(),
		Method:      parts[0],
		URL:         fullURL,
		Path:        path,
		Query:       query,
		HTTPVersion: parts[2],
		Headers:     make(map[string]string),
	}

	// Parse headers
	var contentLength int64 = 0
	for {
		line, _, err := reader.ReadLine()
		if err != nil || len(line) == 0 {
			break
		}

		headerLine := string(line)
		if colonIdx := strings.Index(headerLine, ":"); colonIdx != -1 {
			key := strings.TrimSpace(headerLine[:colonIdx])
			value := strings.TrimSpace(headerLine[colonIdx+1:])

			// Store all headers
			capture.Headers[key] = value

			// Extract key headers for easy access
			switch strings.ToLower(key) {
			case "content-type":
				capture.ContentType = value
			case "user-agent":
				capture.UserAgent = value
			case "referer":
				capture.Referer = value
			case "content-length":
				if cl, err := strconv.ParseInt(value, 10, 64); err == nil {
					contentLength = cl
				}
			}
		}
	}

	// Read body if present (after the double CRLF)
	if headerEndIndex < len(data) && headerEndIndex+4 < len(data) {
		bodyData := data[headerEndIndex+4:] // Skip the \r\n\r\n
		if len(bodyData) > 0 {
			// For binary data, we might want to base64 encode, but for now treat as string
			capture.Body = string(bodyData)
			capture.BodySize = len(bodyData)
		}
	} else if contentLength > 0 {
		// If we have content-length but no body in this packet, note the expected size
		capture.BodySize = int(contentLength)
	}

	// Ensure BodySize is set correctly based on actual body content
	if capture.Body != "" && capture.BodySize == 0 {
		capture.BodySize = len(capture.Body)
	}

	return capture, nil
}

// Save HTTP capture to disk with enhanced details
func (ps *ProxyServer) saveCapture(capture *HTTPCapture) {
	timestamp := capture.Timestamp.Format("2006-01-02_15-04-05.000")

	// Create more descriptive filename including method and path
	safeMethod := strings.ToLower(capture.Method)
	safePath := strings.ReplaceAll(capture.Path, "/", "_")
	if safePath == "" || safePath == "_" {
		safePath = "root"
	}
	if len(safePath) > 50 {
		safePath = safePath[:50]
	}

	filename := fmt.Sprintf("%s_[%s]_%s_%s_%s.json",
		timestamp, capture.ClientIP, capture.Domain, safeMethod, safePath)
	filename = strings.ReplaceAll(filename, ":", "_")
	filename = strings.ReplaceAll(filename, "?", "_")
	filename = strings.ReplaceAll(filename, "&", "_")

	filepath := filepath.Join(ps.config.Logging.CaptureDir, filename)

	data, err := json.MarshalIndent(capture, "", "  ")
	if err != nil {
		log.Printf("Error marshaling capture: %v", err)
		return
	}

	err = os.WriteFile(filepath, data, 0644)
	if err != nil {
		log.Printf("Error saving capture: %v", err)
		return
	}

	// Log what was captured
	log.Printf("Captured request saved: %s %s (%d headers, %d bytes body) -> %s",
		capture.Method, capture.URL, len(capture.Headers), capture.BodySize, filename)

	ps.mutex.Lock()
	ps.stats.CapturedRequests++
	ps.mutex.Unlock()
}

// Handle HTTP inspection with enhanced request reconstruction
func (ps *ProxyServer) inspectHTTP(data []byte, clientIP, domain string) bool {
	capture := ps.inspectHTTPWithCapture(data, clientIP, domain)
	if capture != nil {
		ps.saveCapture(capture)
		return true
	}
	return false
}

// Handle HTTP inspection and return the capture object (for use with response matching)
func (ps *ProxyServer) inspectHTTPWithCapture(data []byte, clientIP, domain string) *HTTPCapture {
	// Look for HTTP request start patterns
	if !bytes.HasPrefix(data, []byte("GET ")) &&
		!bytes.HasPrefix(data, []byte("POST ")) &&
		!bytes.HasPrefix(data, []byte("PUT ")) &&
		!bytes.HasPrefix(data, []byte("DELETE ")) &&
		!bytes.HasPrefix(data, []byte("HEAD ")) &&
		!bytes.HasPrefix(data, []byte("OPTIONS ")) &&
		!bytes.HasPrefix(data, []byte("PATCH ")) &&
		!bytes.HasPrefix(data, []byte("TRACE ")) &&
		!bytes.HasPrefix(data, []byte("CONNECT ")) {
		return nil
	}

	// Parse the complete HTTP request as a single entity
	capture, err := parseHTTPRequest(data)
	if err != nil {
		if ps.config.Logging.EnableDebug {
			log.Printf("Error parsing HTTP request: %v", err)
		}
		return nil
	}

	capture.ClientIP = clientIP
	capture.Domain = domain

	// Log the captured request details
	if ps.config.Logging.EnableDebug {
		log.Printf("Captured %s %s from %s to %s (Headers: %d, Body: %d bytes)",
			capture.Method, capture.URL, clientIP, domain, len(capture.Headers), capture.BodySize)
	}

	return capture
}

// Fast relay without inspection
func (ps *ProxyServer) relayFast(dst, src net.Conn, buffer []byte, counter *int64) {
	defer dst.Close()
	defer src.Close()

	for {
		if err := src.SetReadDeadline(time.Now().Add(time.Duration(ps.config.Proxy.ReadTimeout) * time.Second)); err != nil {
			return
		}
		n, err := src.Read(buffer)
		if err != nil {
			return
		}

		*counter += int64(n)

		if err := dst.SetWriteDeadline(time.Now().Add(time.Duration(ps.config.Proxy.WriteTimeout) * time.Second)); err != nil {
			return
		}
		if _, err = dst.Write(buffer[:n]); err != nil {
			return
		}
	}
}

// Relay with inspection
func (ps *ProxyServer) relayWithInspection(dst, src net.Conn, buffer []byte, counter *int64, clientIP, domain string, isRequest bool, info *ConnectionInfo) {
	defer dst.Close()
	defer src.Close()

	for {
		if err := src.SetReadDeadline(time.Now().Add(time.Duration(ps.config.Proxy.ReadTimeout) * time.Second)); err != nil {
			return
		}
		n, err := src.Read(buffer)
		if err != nil {
			return
		}

		*counter += int64(n)

		// Inspect data if it's a request
		if isRequest {
			if ps.inspectHTTP(buffer[:n], clientIP, domain) {
				info.Captured = true
			}
		}

		if err := dst.SetWriteDeadline(time.Now().Add(time.Duration(ps.config.Proxy.WriteTimeout) * time.Second)); err != nil {
			return
		}
		if _, err = dst.Write(buffer[:n]); err != nil {
			return
		}
	}
}

// Handle individual connection
func (ps *ProxyServer) handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	ps.mutex.Lock()
	ps.stats.TotalConnections++
	ps.stats.ActiveConnections++
	ps.mutex.Unlock()

	defer func() {
		ps.mutex.Lock()
		ps.stats.ActiveConnections--
		ps.mutex.Unlock()
	}()

	// Extract client IP properly handling both IPv4 and IPv6
	clientAddr := clientConn.RemoteAddr().String()
	clientIP := clientAddr
	if host, _, err := net.SplitHostPort(clientAddr); err == nil {
		clientIP = host
	}

	// Peek at first packet
	peekBuffer := make([]byte, 4096)
	if err := clientConn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return
	}
	n, err := clientConn.Read(peekBuffer)
	if err != nil {
		return
	}
	if err := clientConn.SetReadDeadline(time.Time{}); err != nil {
		return
	}

	// Extract destination info
	var domain, serverAddr string

	if ps.config.Proxy.Transparent {
		// In transparent mode, extract from SNI or Host header
		domain = extractSNI(peekBuffer[:n])
		if domain == "" {
			domain = extractHTTPHost(peekBuffer[:n])
		}

		if domain != "" {
			// Determine port based on protocol
			if peekBuffer[0] == 0x16 { // TLS
				serverAddr = domain + ":443"
			} else {
				serverAddr = domain + ":80"
			}
		}
	} else {
		// Explicit proxy mode - parse CONNECT request
		if bytes.HasPrefix(peekBuffer[:n], []byte("CONNECT ")) {
			scanner := bufio.NewScanner(bytes.NewReader(peekBuffer[:n]))
			if scanner.Scan() {
				parts := strings.Fields(scanner.Text())
				if len(parts) >= 2 {
					serverAddr = parts[1]
					// Extract domain from serverAddr (handle both domain:port and domain formats)
					if colonIndex := strings.Index(serverAddr, ":"); colonIndex != -1 {
						domain = serverAddr[:colonIndex]
					} else {
						domain = serverAddr
						// If no port specified, add default port
						if peekBuffer[0] == 0x16 { // TLS
							serverAddr = domain + ":443"
						} else {
							serverAddr = domain + ":80"
						}
					}
				}
			}
		} else {
			// Handle non-CONNECT requests in explicit mode (HTTP GET, POST, etc.)
			domain = extractHTTPHost(peekBuffer[:n])
			if domain != "" {
				// For HTTP requests, use port 80
				serverAddr = domain + ":80"
			}
		}
	}

	if domain == "" || serverAddr == "" {
		log.Printf("Could not determine destination for connection from %s", clientIP)
		return
	}

	// Connect to target server
	serverConn, err := net.DialTimeout("tcp", serverAddr, 10*time.Second)
	if err != nil {
		log.Printf("Failed to connect to %s: %v", serverAddr, err)
		return
	}

	// Create connection info
	info := &ConnectionInfo{
		ClientIP:   clientIP,
		ServerAddr: serverAddr,
		Domain:     domain,
		Protocol:   "HTTP",
		StartTime:  time.Now(),
		Inspected:  ps.shouldInspect(clientIP, domain),
	}

	if peekBuffer[0] == 0x16 {
		info.Protocol = "HTTPS"
	}

	// Determine if this is HTTPS and a CONNECT request
	isConnect := !ps.config.Proxy.Transparent && bytes.HasPrefix(peekBuffer[:n], []byte("CONNECT "))
	isHTTPS := strings.HasSuffix(serverAddr, ":443") || peekBuffer[0] == 0x16

	// Handle HTTPS interception for inspected connections
	if info.Inspected && isHTTPS && isConnect {
		serverConn.Close() // Close the connection we opened, we'll handle this differently
		ps.handleHTTPSInterception(clientConn, domain, info)
		return
	}

	// Handle regular connections
	if isConnect {
		if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
			return
		}
	} else {
		// For HTTP requests, inspect the peeked data before forwarding
		if info.Inspected {
			if ps.inspectHTTP(peekBuffer[:n], clientIP, domain) {
				info.Captured = true
			}
		}

		// Forward the peeked data
		if _, err := serverConn.Write(peekBuffer[:n]); err != nil {
			return
		}
	}

	// Get buffers from pool
	buffer1 := *ps.bufferPool.Get().(*[]byte)
	buffer2 := *ps.bufferPool.Get().(*[]byte)
	defer ps.bufferPool.Put(&buffer1)
	defer ps.bufferPool.Put(&buffer2)

	// Start bidirectional relay
	done := make(chan bool, 2)

	if info.Inspected {
		ps.mutex.Lock()
		ps.stats.InspectedConnections++
		ps.mutex.Unlock()

		// Client -> Server (with inspection)
		go func() {
			ps.relayWithInspection(serverConn, clientConn, buffer1, &info.BytesRead, clientIP, domain, true, info)
			done <- true
		}()

		// Server -> Client (without inspection)
		go func() {
			ps.relayFast(clientConn, serverConn, buffer2, &info.BytesWrite)
			done <- true
		}()
	} else {
		// Fast relay without inspection
		go func() {
			ps.relayFast(serverConn, clientConn, buffer1, &info.BytesRead)
			done <- true
		}()

		go func() {
			ps.relayFast(clientConn, serverConn, buffer2, &info.BytesWrite)
			done <- true
		}()
	}

	// Wait for completion
	<-done

	// Update stats
	ps.mutex.Lock()
	ps.stats.BytesTransferred += info.BytesRead + info.BytesWrite
	ps.mutex.Unlock()

	// Log connection
	ps.logConnection(info)
}

// Start proxy server
func (ps *ProxyServer) Start() error {
	listener, err := net.Listen("tcp", ps.config.Proxy.ListenAddr)
	if err != nil {
		return err
	}
	defer listener.Close()

	log.Printf("MITM Proxy listening on %s (transparent: %t)",
		ps.config.Proxy.ListenAddr, ps.config.Proxy.Transparent)
	log.Printf("Inspect domains: %v", ps.config.Rules.InspectDomains)
	log.Printf("Inspect IPs: %v", ps.config.Rules.InspectIPs)
	log.Printf("Capture directory: %s", ps.config.Logging.CaptureDir)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}

		go ps.handleConnection(conn)
	}
}

// Get current stats
func (ps *ProxyServer) GetStats() *ProxyStats {
	ps.mutex.RLock()
	defer ps.mutex.RUnlock()

	return &ProxyStats{
		TotalConnections:     ps.stats.TotalConnections,
		ActiveConnections:    ps.stats.ActiveConnections,
		BytesTransferred:     ps.stats.BytesTransferred,
		InspectedConnections: ps.stats.InspectedConnections,
		CapturedRequests:     ps.stats.CapturedRequests,
	}
}

// Generate or load CA certificate
func (ps *ProxyServer) loadOrGenerateCA() error {
	caFile := ps.config.TLS.CAFile
	keyFile := ps.config.TLS.CAKeyFile

	// Try to load existing CA
	if _, err := os.Stat(caFile); err == nil {
		if _, err := os.Stat(keyFile); err == nil {
			return ps.loadCA(caFile, keyFile)
		}
	}

	// Generate new CA if auto-generate is enabled
	if ps.config.TLS.AutoGenerate {
		return ps.generateCA(caFile, keyFile)
	}

	return fmt.Errorf("CA certificate not found and auto-generate is disabled")
}

// Load existing CA certificate
func (ps *ProxyServer) loadCA(certFile, keyFile string) error {
	// Load certificate
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return err
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return fmt.Errorf("failed to parse certificate PEM")
	}

	ps.caCert, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}

	// Load private key
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return err
	}

	block, _ = pem.Decode(keyPEM)
	if block == nil {
		return fmt.Errorf("failed to parse key PEM")
	}

	ps.caKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return err
	}

	log.Printf("Loaded CA certificate: %s", ps.caCert.Subject.CommonName)
	return nil
}

// Generate new CA certificate
func (ps *ProxyServer) generateCA(certFile, keyFile string) error {
	// Generate private key
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"Gander MITM Proxy"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{""},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
			CommonName:    "Gander MITM CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Duration(ps.config.TLS.ValidDays*24) * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return err
	}

	// Parse certificate
	ps.caCert, err = x509.ParseCertificate(certDER)
	if err != nil {
		return err
	}
	ps.caKey = key

	// Create cert directory
	if err := os.MkdirAll(ps.config.TLS.CertDir, 0755); err != nil {
		return err
	}

	// Save certificate
	certOut, err := os.Create(certFile)
	if err != nil {
		return err
	}
	defer certOut.Close()

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return err
	}

	// Save private key
	keyOut, err := os.Create(keyFile)
	if err != nil {
		return err
	}
	defer keyOut.Close()

	if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}); err != nil {
		return err
	}

	log.Printf("Generated CA certificate: %s", ps.caCert.Subject.CommonName)
	return nil
}

// Get certificate for domain (with caching and optional sniffing)
func (ps *ProxyServer) getCertForDomain(domain, serverAddr string) (*tls.Certificate, error) {
	ps.certMutex.RLock()
	if cert, exists := ps.certCache[domain]; exists {
		ps.certMutex.RUnlock()
		return cert, nil
	}
	ps.certMutex.RUnlock()

	// Generate new certificate with optional upstream sniffing
	cert, err := ps.generateCertForDomainWithSniffing(domain, serverAddr)
	if err != nil {
		return nil, err
	}

	// Cache certificate
	ps.certMutex.Lock()
	ps.certCache[domain] = cert
	ps.certMutex.Unlock()

	return cert, nil
}

// Handle HTTPS interception with certificate substitution
func (ps *ProxyServer) handleHTTPSInterception(clientConn net.Conn, domain string, info *ConnectionInfo) {
	// Send 200 OK for CONNECT
	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
		return
	}

	// Get certificate for domain
	cert, err := ps.getCertForDomain(domain, info.ServerAddr)
	if err != nil {
		log.Printf("Failed to get certificate for %s: %v", domain, err)
		return
	}

	// Create TLS config with generated certificate
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*cert},
		ServerName:   domain,
	}

	// Upgrade client connection to TLS
	clientTLSConn := tls.Server(clientConn, tlsConfig)
	if err := clientTLSConn.Handshake(); err != nil {
		log.Printf("TLS handshake failed for %s: %v", domain, err)
		return
	}
	defer clientTLSConn.Close()

	// Connect to real server
	serverConn, err := tls.Dial("tcp", info.ServerAddr, &tls.Config{
		ServerName:         domain,
		InsecureSkipVerify: true, // We're intercepting, so we skip verification
	})
	if err != nil {
		log.Printf("Failed to connect to %s: %v", info.ServerAddr, err)
		return
	}
	defer serverConn.Close()

	ps.mutex.Lock()
	ps.stats.InspectedConnections++
	ps.mutex.Unlock()

	// Get buffers from pool
	buffer1 := *ps.bufferPool.Get().(*[]byte)
	buffer2 := *ps.bufferPool.Get().(*[]byte)
	defer ps.bufferPool.Put(&buffer1)
	defer ps.bufferPool.Put(&buffer2)

	// Start bidirectional relay - use inspection only if needed
	done := make(chan bool, 2)

	// Check if this connection should be inspected
	shouldInspect := ps.shouldInspect(info.ClientIP, domain)

	if shouldInspect {
		// Use inspection relays for capturing HTTP traffic
		capturedRequests := make(chan *HTTPCapture, 10) // Buffer for captured requests

		// Client -> Server (with inspection)
		go func() {
			ps.relayWithHTTPSInspection(serverConn, clientTLSConn, buffer1, &info.BytesRead, info.ClientIP, domain, capturedRequests)
			close(capturedRequests) // Close channel when request relay ends
			done <- true
		}()

		// Server -> Client (with response inspection)
		go func() {
			ps.relayWithHTTPSResponseInspection(clientTLSConn, serverConn, buffer2, &info.BytesWrite, info.ClientIP, domain, capturedRequests)
			done <- true
		}()
	} else {
		// Use fast relays for non-inspected traffic
		go func() {
			ps.relayFast(serverConn, clientTLSConn, buffer1, &info.BytesRead)
			done <- true
		}()

		go func() {
			ps.relayFast(clientTLSConn, serverConn, buffer2, &info.BytesWrite)
			done <- true
		}()
	}

	// Wait for completion
	<-done

	// Update stats
	ps.mutex.Lock()
	ps.stats.BytesTransferred += info.BytesRead + info.BytesWrite
	ps.mutex.Unlock()

	// Mark as captured since we intercepted HTTPS
	info.Captured = true

	// Log connection
	ps.logConnection(info)
}

// Relay with HTTPS inspection (decrypted content)
func (ps *ProxyServer) relayWithHTTPSInspection(dst, src net.Conn, buffer []byte, counter *int64, clientIP, domain string, capturedRequests chan *HTTPCapture) {
	defer dst.Close()
	defer src.Close()

	for {
		if err := src.SetReadDeadline(time.Now().Add(time.Duration(ps.config.Proxy.ReadTimeout) * time.Second)); err != nil {
			return
		}
		n, err := src.Read(buffer)
		if err != nil {
			return
		}

		*counter += int64(n)

		// Inspect decrypted HTTPS data and capture requests
		if capture := ps.inspectHTTPWithCapture(buffer[:n], clientIP, domain); capture != nil {
			// Send captured request to the response handler
			select {
			case capturedRequests <- capture:
			default:
				// Channel is full, skip
			}
		}

		if err := dst.SetWriteDeadline(time.Now().Add(time.Duration(ps.config.Proxy.WriteTimeout) * time.Second)); err != nil {
			return
		}
		if _, err = dst.Write(buffer[:n]); err != nil {
			return
		}
	}
}

// Sniff upstream certificate to extract details for generating matching certificate
func (ps *ProxyServer) sniffUpstreamCert(domain, serverAddr string) (*x509.Certificate, error) {
	// Connect to upstream server with TLS
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", serverAddr, &tls.Config{
		ServerName:         domain,
		InsecureSkipVerify: true, // We just want to sniff the cert, not verify it
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to upstream server: %v", err)
	}
	defer conn.Close()

	// Get the peer certificate chain
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no certificates received from upstream server")
	}

	// Return the leaf certificate (first in chain)
	upstreamCert := state.PeerCertificates[0]

	if ps.config.Logging.EnableDebug {
		log.Printf("Sniffed upstream cert for %s: CN=%s, SAN=%v, Org=%v",
			domain, upstreamCert.Subject.CommonName, upstreamCert.DNSNames, upstreamCert.Subject.Organization)
	}

	return upstreamCert, nil
}

// Generate certificate for domain with optional upstream certificate sniffing
func (ps *ProxyServer) generateCertForDomainWithSniffing(domain, serverAddr string) (*tls.Certificate, error) {
	// Generate private key
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	// Create base certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			Organization:  []string{"Gander MITM Proxy"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{""},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
			CommonName:    domain,
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(time.Duration(ps.config.TLS.ValidDays*24) * time.Hour),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{},
		DNSNames:    []string{domain},
	}

	// If upstream certificate sniffing is enabled, try to mimic the upstream certificate
	if ps.config.TLS.UpstreamCertSniff {
		upstreamCert, err := ps.sniffUpstreamCert(domain, serverAddr)
		if err != nil {
			if ps.config.Logging.EnableDebug {
				log.Printf("Failed to sniff upstream cert for %s: %v, using default template", domain, err)
			}
		} else {
			// Copy relevant fields from upstream certificate
			template.Subject.Organization = upstreamCert.Subject.Organization
			template.Subject.OrganizationalUnit = upstreamCert.Subject.OrganizationalUnit
			template.Subject.Country = upstreamCert.Subject.Country
			template.Subject.Province = upstreamCert.Subject.Province
			template.Subject.Locality = upstreamCert.Subject.Locality
			template.Subject.StreetAddress = upstreamCert.Subject.StreetAddress
			template.Subject.PostalCode = upstreamCert.Subject.PostalCode

			// Use the upstream Common Name if it matches the domain
			if upstreamCert.Subject.CommonName == domain || strings.HasPrefix(domain, "*.") {
				template.Subject.CommonName = upstreamCert.Subject.CommonName
			}

			// Copy Subject Alternative Names (SANs)
			template.DNSNames = append(template.DNSNames, upstreamCert.DNSNames...)

			// Ensure our target domain is included
			domainFound := false
			for _, name := range template.DNSNames {
				if name == domain {
					domainFound = true
					break
				}
			}
			if !domainFound {
				template.DNSNames = append(template.DNSNames, domain)
			}

			// Copy IP addresses
			template.IPAddresses = make([]net.IP, len(upstreamCert.IPAddresses))
			copy(template.IPAddresses, upstreamCert.IPAddresses)

			if ps.config.Logging.EnableDebug {
				log.Printf("Generated certificate for %s using upstream cert template: CN=%s, SAN=%v",
					domain, template.Subject.CommonName, template.DNSNames)
			}
		}
	}

	// Handle wildcard domains
	if strings.HasPrefix(domain, "*.") {
		template.DNSNames = append(template.DNSNames, domain[2:])
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, ps.caCert, &key.PublicKey, ps.caKey)
	if err != nil {
		return nil, err
	}

	// Create TLS certificate
	cert := &tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}

	return cert, nil
}

// Parse HTTP response with enhanced details
func parseHTTPResponse(data []byte) (*HTTPResponse, error) {
	// Find the end of headers (double CRLF)
	headerEndIndex := bytes.Index(data, []byte("\r\n\r\n"))
	if headerEndIndex == -1 {
		// If no double CRLF found, treat entire data as headers (incomplete response)
		headerEndIndex = len(data)
	}

	headerData := data[:headerEndIndex]
	reader := bufio.NewReader(bytes.NewReader(headerData))

	// Parse status line
	statusLine, _, err := reader.ReadLine()
	if err != nil {
		return nil, err
	}

	statusParts := strings.Fields(string(statusLine))
	if len(statusParts) < 2 {
		return nil, fmt.Errorf("invalid HTTP response status line")
	}

	// Parse status code
	statusCode, err := strconv.Atoi(statusParts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid status code: %v", err)
	}

	response := &HTTPResponse{
		StatusCode: statusCode,
		Headers:    make(map[string]string),
	}

	// Parse headers
	for {
		line, _, err := reader.ReadLine()
		if err != nil || len(line) == 0 {
			break
		}

		headerLine := string(line)
		if colonIdx := strings.Index(headerLine, ":"); colonIdx != -1 {
			key := strings.TrimSpace(headerLine[:colonIdx])
			value := strings.TrimSpace(headerLine[colonIdx+1:])

			// Store all headers
			response.Headers[key] = value
		}
	}

	// Read body if present (after the double CRLF)
	if headerEndIndex < len(data) && headerEndIndex+4 < len(data) {
		bodyData := data[headerEndIndex+4:] // Skip the \r\n\r\n
		if len(bodyData) > 0 {
			// For binary data, we might want to base64 encode, but for now treat as string
			response.Body = string(bodyData)
			response.BodySize = len(bodyData)
		}
	}

	return response, nil
}

// Handle HTTP response inspection
func (ps *ProxyServer) inspectHTTPResponse(data []byte, clientIP, domain string, requestCapture *HTTPCapture) {
	// Look for HTTP response start patterns
	if !bytes.HasPrefix(data, []byte("HTTP/1.0 ")) &&
		!bytes.HasPrefix(data, []byte("HTTP/1.1 ")) &&
		!bytes.HasPrefix(data, []byte("HTTP/2.0 ")) {
		return
	}

	// Parse the HTTP response
	response, err := parseHTTPResponse(data)
	if err != nil {
		if ps.config.Logging.EnableDebug {
			log.Printf("Error parsing HTTP response: %v", err)
		}
		return
	}

	// If we have a matching request capture, attach the response to it
	if requestCapture != nil {
		requestCapture.Response = response

		// Re-save the capture with the response included
		ps.saveCapture(requestCapture)

		if ps.config.Logging.EnableDebug {
			log.Printf("Captured response %d for %s %s from %s to %s (Headers: %d, Body: %d bytes)",
				response.StatusCode, requestCapture.Method, requestCapture.URL, clientIP, domain,
				len(response.Headers), response.BodySize)
		}
	}
}

// Relay with HTTPS response inspection (for server -> client traffic)
func (ps *ProxyServer) relayWithHTTPSResponseInspection(dst, src net.Conn, buffer []byte, counter *int64, clientIP, domain string, capturedRequests chan *HTTPCapture) {
	defer dst.Close()
	defer src.Close()

	var currentRequest *HTTPCapture

	for {
		if err := src.SetReadDeadline(time.Now().Add(time.Duration(ps.config.Proxy.ReadTimeout) * time.Second)); err != nil {
			return
		}
		n, err := src.Read(buffer)
		if err != nil {
			return
		}

		*counter += int64(n)

		// Try to get a captured request if we don't have one
		if currentRequest == nil {
			select {
			case req, ok := <-capturedRequests:
				if ok {
					currentRequest = req
				}
			default:
				// No request available yet
			}
		}

		// Inspect HTTP response data
		ps.inspectHTTPResponse(buffer[:n], clientIP, domain, currentRequest)

		if err := dst.SetWriteDeadline(time.Now().Add(time.Duration(ps.config.Proxy.WriteTimeout) * time.Second)); err != nil {
			return
		}
		if _, err = dst.Write(buffer[:n]); err != nil {
			return
		}
	}
}

func main() {
	if len(os.Args) < 2 {
		log.Fatal("Usage: ./mitm-proxy <config.json>")
	}

	config, err := loadConfig(os.Args[1])
	if err != nil {
		log.Fatalf("Error loading config: %v", err)
	}

	proxy, err := NewProxyServer(config)
	if err != nil {
		log.Fatalf("Error creating proxy: %v", err)
	}

	// Start stats reporter
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		for range ticker.C {
			stats := proxy.GetStats()
			log.Printf("Stats: %d total, %d active, %d inspected, %d captured, %d MB transferred",
				stats.TotalConnections,
				stats.ActiveConnections,
				stats.InspectedConnections,
				stats.CapturedRequests,
				stats.BytesTransferred/1024/1024)
		}
	}()

	err = proxy.Start()
	if err != nil {
		log.Fatalf("Error starting proxy: %v", err)
	}
}
