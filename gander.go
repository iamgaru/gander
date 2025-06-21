package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
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
		CertFile     string `json:"cert_file"`
		KeyFile      string `json:"key_file"`
		CAFile       string `json:"ca_file"`
		CAKeyFile    string `json:"ca_key_file"`
		CertDir      string `json:"cert_dir"`
		AutoGenerate bool   `json:"auto_generate"`
		ValidDays    int    `json:"valid_days"`
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

// HTTP request capture
type HTTPCapture struct {
	Timestamp time.Time         `json:"timestamp"`
	ClientIP  string            `json:"client_ip"`
	Domain    string            `json:"domain"`
	Method    string            `json:"method"`
	URL       string            `json:"url"`
	Headers   map[string]string `json:"headers"`
	Body      string            `json:"body,omitempty"`
	Response  *HTTPResponse     `json:"response,omitempty"`
}

type HTTPResponse struct {
	StatusCode int               `json:"status_code"`
	Headers    map[string]string `json:"headers"`
	Body       string            `json:"body,omitempty"`
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

	return &ProxyServer{
		config:         config,
		inspectDomains: inspectDomains,
		inspectIPs:     inspectIPs,
		bypassDomains:  bypassDomains,
		bypassIPs:      bypassIPs,
		logFile:        logFile,
		bufferPool:     bufferPool,
		stats:          &ProxyStats{},
	}, nil
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

// Parse HTTP request
func parseHTTPRequest(data []byte) (*HTTPCapture, error) {
	reader := bufio.NewReader(bytes.NewReader(data))

	// Parse request line
	requestLine, _, err := reader.ReadLine()
	if err != nil {
		return nil, err
	}

	parts := strings.Fields(string(requestLine))
	if len(parts) < 3 {
		return nil, fmt.Errorf("invalid HTTP request line")
	}

	capture := &HTTPCapture{
		Timestamp: time.Now(),
		Method:    parts[0],
		URL:       parts[1],
		Headers:   make(map[string]string),
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
			capture.Headers[key] = value
		}
	}

	// Read body if present
	remaining, err := io.ReadAll(reader)
	if err == nil && len(remaining) > 0 {
		capture.Body = string(remaining)
	}

	return capture, nil
}

// Save HTTP capture to disk
func (ps *ProxyServer) saveCapture(capture *HTTPCapture) {
	timestamp := capture.Timestamp.Format("2006-01-02_15-04-05.000")
	filename := fmt.Sprintf("%s_%s_%s.json", timestamp, capture.ClientIP, capture.Domain)
	filename = strings.ReplaceAll(filename, ":", "_")

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

	ps.mutex.Lock()
	ps.stats.CapturedRequests++
	ps.mutex.Unlock()
}

// Handle HTTP inspection
func (ps *ProxyServer) inspectHTTP(data []byte, clientIP, domain string) {
	if !bytes.HasPrefix(data, []byte("GET ")) &&
		!bytes.HasPrefix(data, []byte("POST ")) &&
		!bytes.HasPrefix(data, []byte("PUT ")) &&
		!bytes.HasPrefix(data, []byte("DELETE ")) &&
		!bytes.HasPrefix(data, []byte("HEAD ")) &&
		!bytes.HasPrefix(data, []byte("OPTIONS ")) {
		return
	}

	capture, err := parseHTTPRequest(data)
	if err != nil {
		if ps.config.Logging.EnableDebug {
			log.Printf("Error parsing HTTP request: %v", err)
		}
		return
	}

	capture.ClientIP = clientIP
	capture.Domain = domain

	ps.saveCapture(capture)
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
func (ps *ProxyServer) relayWithInspection(dst, src net.Conn, buffer []byte, counter *int64, clientIP, domain string, isRequest bool) {
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
			ps.inspectHTTP(buffer[:n], clientIP, domain)
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

	clientIP := strings.Split(clientConn.RemoteAddr().String(), ":")[0]

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
					domain = strings.Split(serverAddr, ":")[0]
				}
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

	// If explicit proxy mode, send 200 OK for CONNECT
	if !ps.config.Proxy.Transparent && bytes.HasPrefix(peekBuffer[:n], []byte("CONNECT ")) {
		if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
			return
		}
	} else {
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
			ps.relayWithInspection(serverConn, clientConn, buffer1, &info.BytesRead, clientIP, domain, true)
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
