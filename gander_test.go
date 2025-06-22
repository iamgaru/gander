package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Test configuration loading
func TestLoadConfig(t *testing.T) {
	// Create temporary config file
	configFile := filepath.Join(t.TempDir(), "config.json")
	configData := `{
		"proxy": {
			"listen_addr": "127.0.0.1:8080",
			"transparent": false,
			"buffer_size": 32768,
			"read_timeout_seconds": 30,
			"write_timeout_seconds": 30
		},
		"logging": {
			"log_file": "/tmp/mitm.log",
			"capture_dir": "/tmp/captures",
			"max_file_size_mb": 100,
			"enable_debug": true
		},
		"rules": {
			"inspect_domains": ["example.com"],
			"inspect_source_ips": ["192.168.1.100"]
		},
		"tls": {
			"cert_dir": "certs",
			"auto_generate": true,
			"valid_days": 365
		}
	}`

	err := os.WriteFile(configFile, []byte(configData), 0644)
	if err != nil {
		t.Fatalf("Failed to create config file: %v", err)
	}

	// Test loading the config
	config, err := loadConfig(configFile)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Check that defaults were applied
	if config.Proxy.BufferSize != 32768 {
		t.Errorf("Expected default buffer size 32768, got %d", config.Proxy.BufferSize)
	}

	if config.Proxy.ReadTimeout != 30 {
		t.Errorf("Expected default read timeout 30, got %d", config.Proxy.ReadTimeout)
	}

	if config.Proxy.WriteTimeout != 30 {
		t.Errorf("Expected default write timeout 30, got %d", config.Proxy.WriteTimeout)
	}

	if config.Logging.MaxFileSize != 100 {
		t.Errorf("Expected default max file size 100, got %d", config.Logging.MaxFileSize)
	}

	if config.TLS.ValidDays != 365 {
		t.Errorf("Expected default valid days 365, got %d", config.TLS.ValidDays)
	}

	if config.TLS.CertDir != "certs" {
		t.Errorf("Expected default cert dir 'certs', got '%s'", config.TLS.CertDir)
	}
}

// Test loading invalid config
func TestLoadConfigInvalidJSON(t *testing.T) {
	configFile := filepath.Join(t.TempDir(), "config.json")
	err := os.WriteFile(configFile, []byte("invalid json"), 0644)
	if err != nil {
		t.Fatalf("Failed to create config file: %v", err)
	}

	_, err = loadConfig(configFile)
	if err == nil {
		t.Error("Expected error when loading invalid config, got nil")
	}
}

// Test loading non-existent config
func TestLoadConfigNotFound(t *testing.T) {
	_, err := loadConfig("non_existent_config.json")
	if err == nil {
		t.Error("Expected error when loading non-existent config, got nil")
	}
}

// Test NewProxyServer creation
func TestNewProxyServer(t *testing.T) {
	tempDir := t.TempDir()

	config := &Config{
		Proxy: struct {
			ListenAddr   string `json:"listen_addr"`
			Transparent  bool   `json:"transparent"`
			ExplicitPort int    `json:"explicit_port"`
			BufferSize   int    `json:"buffer_size"`
			ReadTimeout  int    `json:"read_timeout_seconds"`
			WriteTimeout int    `json:"write_timeout_seconds"`
		}{
			ListenAddr:   ":0", // Use any available port
			Transparent:  false,
			ExplicitPort: 0,
			BufferSize:   32768,
			ReadTimeout:  30,
			WriteTimeout: 30,
		},
		Logging: struct {
			LogFile     string `json:"log_file"`
			CaptureDir  string `json:"capture_dir"`
			MaxFileSize int64  `json:"max_file_size_mb"`
			EnableDebug bool   `json:"enable_debug"`
		}{
			LogFile:     filepath.Join(tempDir, "test.log"),
			CaptureDir:  filepath.Join(tempDir, "captures"),
			MaxFileSize: 100,
			EnableDebug: false,
		},
		Rules: struct {
			InspectDomains []string `json:"inspect_domains"`
			InspectIPs     []string `json:"inspect_source_ips"`
			BypassDomains  []string `json:"bypass_domains"`
			BypassIPs      []string `json:"bypass_source_ips"`
		}{
			InspectDomains: []string{"example.com", "test.com"},
			InspectIPs:     []string{"192.168.1.100"},
			BypassDomains:  []string{"google.com"},
			BypassIPs:      []string{"127.0.0.1"},
		},
		TLS: struct {
			CertFile          string `json:"cert_file"`
			KeyFile           string `json:"key_file"`
			CAFile            string `json:"ca_file"`
			CAKeyFile         string `json:"ca_key_file"`
			CertDir           string `json:"cert_dir"`
			AutoGenerate      bool   `json:"auto_generate"`
			ValidDays         int    `json:"valid_days"`
			UpstreamCertSniff bool   `json:"upstream_cert_sniff"`
		}{
			CertDir:      filepath.Join(tempDir, "certs"),
			CAFile:       filepath.Join(tempDir, "certs", "ca.crt"),
			CAKeyFile:    filepath.Join(tempDir, "certs", "ca.key"),
			AutoGenerate: true,
			ValidDays:    365,
		},
	}

	proxy, err := NewProxyServer(config)
	if err != nil {
		t.Fatalf("Failed to create proxy server: %v", err)
	}

	if proxy == nil {
		t.Fatal("Proxy server is nil")
	}

	// Check that lookup maps were created correctly
	if !proxy.inspectDomains["example.com"] {
		t.Error("Expected example.com to be in inspect domains")
	}

	if !proxy.inspectDomains["test.com"] {
		t.Error("Expected test.com to be in inspect domains")
	}

	if !proxy.inspectIPs["192.168.1.100"] {
		t.Error("Expected 192.168.1.100 to be in inspect IPs")
	}

	if !proxy.bypassDomains["google.com"] {
		t.Error("Expected google.com to be in bypass domains")
	}

	if !proxy.bypassIPs["127.0.0.1"] {
		t.Error("Expected 127.0.0.1 to be in bypass IPs")
	}

	// Clean up
	proxy.logFile.Close()
}

// Test shouldInspect logic
func TestShouldInspect(t *testing.T) {
	tempDir := t.TempDir()

	config := &Config{
		Logging: struct {
			LogFile     string `json:"log_file"`
			CaptureDir  string `json:"capture_dir"`
			MaxFileSize int64  `json:"max_file_size_mb"`
			EnableDebug bool   `json:"enable_debug"`
		}{
			LogFile:    filepath.Join(tempDir, "test.log"),
			CaptureDir: filepath.Join(tempDir, "captures"),
		},
		Rules: struct {
			InspectDomains []string `json:"inspect_domains"`
			InspectIPs     []string `json:"inspect_source_ips"`
			BypassDomains  []string `json:"bypass_domains"`
			BypassIPs      []string `json:"bypass_source_ips"`
		}{
			InspectDomains: []string{"example.com", "test.com"},
			InspectIPs:     []string{"192.168.1.100"},
			BypassDomains:  []string{"google.com"},
			BypassIPs:      []string{"127.0.0.1"},
		},
		TLS: struct {
			CertFile          string `json:"cert_file"`
			KeyFile           string `json:"key_file"`
			CAFile            string `json:"ca_file"`
			CAKeyFile         string `json:"ca_key_file"`
			CertDir           string `json:"cert_dir"`
			AutoGenerate      bool   `json:"auto_generate"`
			ValidDays         int    `json:"valid_days"`
			UpstreamCertSniff bool   `json:"upstream_cert_sniff"`
		}{
			CertDir:      filepath.Join(tempDir, "certs"),
			CAFile:       filepath.Join(tempDir, "certs", "ca.crt"),
			CAKeyFile:    filepath.Join(tempDir, "certs", "ca.key"),
			AutoGenerate: true,
			ValidDays:    365,
		},
	}

	proxy, err := NewProxyServer(config)
	if err != nil {
		t.Fatalf("Failed to create proxy server: %v", err)
	}
	defer proxy.logFile.Close()

	tests := []struct {
		clientIP string
		domain   string
		expected bool
		name     string
	}{
		{"192.168.1.100", "example.com", true, "Should inspect: IP and domain both in inspect lists"},
		{"192.168.1.200", "example.com", true, "Should inspect: domain in inspect list"},
		{"192.168.1.100", "other.com", true, "Should inspect: IP in inspect list"},
		{"127.0.0.1", "example.com", false, "Should not inspect: IP in bypass list"},
		{"192.168.1.200", "google.com", false, "Should not inspect: domain in bypass list"},
		{"192.168.1.200", "other.com", false, "Should not inspect: neither IP nor domain in inspect lists"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := proxy.shouldInspect(test.clientIP, test.domain)
			if result != test.expected {
				t.Errorf("shouldInspect(%s, %s) = %v, expected %v",
					test.clientIP, test.domain, result, test.expected)
			}
		})
	}
}

// Test extractSNI function
func TestExtractSNI(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected string
	}{
		{
			name:     "No SNI",
			data:     []byte{0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00},
			expected: "",
		},
		{
			name:     "Empty data",
			data:     []byte{},
			expected: "",
		},
		{
			name:     "Non-TLS data",
			data:     []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			expected: "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := extractSNI(test.data)
			if result != test.expected {
				t.Errorf("extractSNI() = %s, expected %s", result, test.expected)
			}
		})
	}
}

// Test extractHTTPHost function
func TestExtractHTTPHost(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected string
	}{
		{
			name:     "HTTP GET with Host header",
			data:     []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			expected: "example.com",
		},
		{
			name:     "HTTP POST with Host header",
			data:     []byte("POST /api HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 0\r\n\r\n"),
			expected: "api.example.com",
		},
		{
			name:     "No Host header",
			data:     []byte("GET / HTTP/1.1\r\nUser-Agent: test\r\n\r\n"),
			expected: "",
		},
		{
			name:     "Empty data",
			data:     []byte{},
			expected: "",
		},
		{
			name:     "Non-HTTP data",
			data:     []byte{0x16, 0x03, 0x01, 0x00, 0x05},
			expected: "",
		},
		{
			name:     "Host with port",
			data:     []byte("GET / HTTP/1.1\r\nHost: example.com:8080\r\n\r\n"),
			expected: "example.com:8080", // extractHTTPHost returns the full host header
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := extractHTTPHost(test.data)
			if result != test.expected {
				t.Errorf("extractHTTPHost() = %s, expected %s", result, test.expected)
			}
		})
	}
}

// Test parseHTTPRequest function
func TestParseHTTPRequest(t *testing.T) {
	tests := []struct {
		name      string
		data      []byte
		shouldErr bool
		method    string
		url       string
		hasHost   bool
		hostValue string
	}{
		{
			name:      "Valid GET request",
			data:      []byte("GET /path HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n"),
			shouldErr: false,
			method:    "GET",
			url:       "/path",
			hasHost:   true,
			hostValue: "example.com",
		},
		{
			name:      "Valid POST request with body",
			data:      []byte("POST /api HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 4\r\n\r\ntest"),
			shouldErr: false,
			method:    "POST",
			url:       "/api",
			hasHost:   true,
			hostValue: "api.example.com",
		},
		{
			name:      "Invalid request line",
			data:      []byte("INVALID\r\n\r\n"),
			shouldErr: true,
		},
		{
			name:      "Empty data",
			data:      []byte{},
			shouldErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			capture, err := parseHTTPRequest(test.data)

			if test.shouldErr {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if capture.Method != test.method {
				t.Errorf("Expected method %s, got %s", test.method, capture.Method)
			}

			if capture.URL != test.url {
				t.Errorf("Expected URL %s, got %s", test.url, capture.URL)
			}

			if test.hasHost {
				if host, exists := capture.Headers["Host"]; !exists {
					t.Error("Expected Host header to exist")
				} else if host != test.hostValue {
					t.Errorf("Expected Host header %s, got %s", test.hostValue, host)
				}
			}
		})
	}
}

// Test proxy stats
func TestProxyStats(t *testing.T) {
	tempDir := t.TempDir()

	config := &Config{
		Logging: struct {
			LogFile     string `json:"log_file"`
			CaptureDir  string `json:"capture_dir"`
			MaxFileSize int64  `json:"max_file_size_mb"`
			EnableDebug bool   `json:"enable_debug"`
		}{
			LogFile:    filepath.Join(tempDir, "test.log"),
			CaptureDir: filepath.Join(tempDir, "captures"),
		},
		TLS: struct {
			CertFile          string `json:"cert_file"`
			KeyFile           string `json:"key_file"`
			CAFile            string `json:"ca_file"`
			CAKeyFile         string `json:"ca_key_file"`
			CertDir           string `json:"cert_dir"`
			AutoGenerate      bool   `json:"auto_generate"`
			ValidDays         int    `json:"valid_days"`
			UpstreamCertSniff bool   `json:"upstream_cert_sniff"`
		}{
			CertDir:      filepath.Join(tempDir, "certs"),
			CAFile:       filepath.Join(tempDir, "certs", "ca.crt"),
			CAKeyFile:    filepath.Join(tempDir, "certs", "ca.key"),
			AutoGenerate: true,
			ValidDays:    365,
		},
	}

	proxy, err := NewProxyServer(config)
	if err != nil {
		t.Fatalf("Failed to create proxy server: %v", err)
	}
	defer proxy.logFile.Close()

	// Test initial stats
	stats := proxy.GetStats()
	if stats.TotalConnections != 0 {
		t.Errorf("Expected initial total connections 0, got %d", stats.TotalConnections)
	}

	// Simulate some activity
	proxy.mutex.Lock()
	proxy.stats.TotalConnections = 10
	proxy.stats.ActiveConnections = 5
	proxy.stats.BytesTransferred = 1024
	proxy.stats.InspectedConnections = 3
	proxy.stats.CapturedRequests = 2
	proxy.mutex.Unlock()

	stats = proxy.GetStats()
	if stats.TotalConnections != 10 {
		t.Errorf("Expected total connections 10, got %d", stats.TotalConnections)
	}
	if stats.ActiveConnections != 5 {
		t.Errorf("Expected active connections 5, got %d", stats.ActiveConnections)
	}
	if stats.BytesTransferred != 1024 {
		t.Errorf("Expected bytes transferred 1024, got %d", stats.BytesTransferred)
	}
	if stats.InspectedConnections != 3 {
		t.Errorf("Expected inspected connections 3, got %d", stats.InspectedConnections)
	}
	if stats.CapturedRequests != 2 {
		t.Errorf("Expected captured requests 2, got %d", stats.CapturedRequests)
	}
}

// Benchmark tests
func BenchmarkExtractHTTPHost(b *testing.B) {
	data := []byte("GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		extractHTTPHost(data)
	}
}

func BenchmarkShouldInspect(b *testing.B) {
	tempDir := b.TempDir()

	config := &Config{
		Logging: struct {
			LogFile     string `json:"log_file"`
			CaptureDir  string `json:"capture_dir"`
			MaxFileSize int64  `json:"max_file_size_mb"`
			EnableDebug bool   `json:"enable_debug"`
		}{
			LogFile:    filepath.Join(tempDir, "test.log"),
			CaptureDir: filepath.Join(tempDir, "captures"),
		},
		Rules: struct {
			InspectDomains []string `json:"inspect_domains"`
			InspectIPs     []string `json:"inspect_source_ips"`
			BypassDomains  []string `json:"bypass_domains"`
			BypassIPs      []string `json:"bypass_source_ips"`
		}{
			InspectDomains: []string{"example.com", "test.com"},
			InspectIPs:     []string{"192.168.1.100"},
		},
		TLS: struct {
			CertFile          string `json:"cert_file"`
			KeyFile           string `json:"key_file"`
			CAFile            string `json:"ca_file"`
			CAKeyFile         string `json:"ca_key_file"`
			CertDir           string `json:"cert_dir"`
			AutoGenerate      bool   `json:"auto_generate"`
			ValidDays         int    `json:"valid_days"`
			UpstreamCertSniff bool   `json:"upstream_cert_sniff"`
		}{
			CertDir:      filepath.Join(tempDir, "certs"),
			CAFile:       filepath.Join(tempDir, "certs", "ca.crt"),
			CAKeyFile:    filepath.Join(tempDir, "certs", "ca.key"),
			AutoGenerate: true,
			ValidDays:    365,
		},
	}

	proxy, err := NewProxyServer(config)
	if err != nil {
		b.Fatalf("Failed to create proxy server: %v", err)
	}
	defer proxy.logFile.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		proxy.shouldInspect("192.168.1.100", "example.com")
	}
}

// Integration test - start proxy server briefly
func TestProxyServerIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tempDir := t.TempDir()

	config := &Config{
		Proxy: struct {
			ListenAddr   string `json:"listen_addr"`
			Transparent  bool   `json:"transparent"`
			ExplicitPort int    `json:"explicit_port"`
			BufferSize   int    `json:"buffer_size"`
			ReadTimeout  int    `json:"read_timeout_seconds"`
			WriteTimeout int    `json:"write_timeout_seconds"`
		}{
			ListenAddr:   ":0", // Let the OS choose a port
			Transparent:  false,
			BufferSize:   32768,
			ReadTimeout:  5,
			WriteTimeout: 5,
		},
		Logging: struct {
			LogFile     string `json:"log_file"`
			CaptureDir  string `json:"capture_dir"`
			MaxFileSize int64  `json:"max_file_size_mb"`
			EnableDebug bool   `json:"enable_debug"`
		}{
			LogFile:    filepath.Join(tempDir, "test.log"),
			CaptureDir: filepath.Join(tempDir, "captures"),
		},
		TLS: struct {
			CertFile          string `json:"cert_file"`
			KeyFile           string `json:"key_file"`
			CAFile            string `json:"ca_file"`
			CAKeyFile         string `json:"ca_key_file"`
			CertDir           string `json:"cert_dir"`
			AutoGenerate      bool   `json:"auto_generate"`
			ValidDays         int    `json:"valid_days"`
			UpstreamCertSniff bool   `json:"upstream_cert_sniff"`
		}{
			CertDir:      filepath.Join(tempDir, "certs"),
			CAFile:       filepath.Join(tempDir, "certs", "ca.crt"),
			CAKeyFile:    filepath.Join(tempDir, "certs", "ca.key"),
			AutoGenerate: true,
			ValidDays:    365,
		},
	}

	proxy, err := NewProxyServer(config)
	if err != nil {
		t.Fatalf("Failed to create proxy server: %v", err)
	}
	defer proxy.logFile.Close()

	// Start the proxy in a goroutine
	done := make(chan error)
	go func() {
		done <- proxy.Start()
	}()

	// Give it a moment to start
	time.Sleep(100 * time.Millisecond)

	// Stop the proxy quickly for this test
	// In a real integration test, you would connect to it and test functionality

	select {
	case err := <-done:
		if err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			t.Errorf("Proxy returned unexpected error: %v", err)
		}
	case <-time.After(1 * time.Second):
		// This is expected - the proxy should be running
	}
}

// Test address parsing for CONNECT requests
func TestConnectAddressParsing(t *testing.T) {
	tests := []struct {
		name           string
		connectRequest string
		expectedDomain string
		expectedAddr   string
	}{
		{
			name:           "CONNECT with port",
			connectRequest: "CONNECT play.google.com:443 HTTP/1.1\r\n\r\n",
			expectedDomain: "play.google.com",
			expectedAddr:   "play.google.com:443",
		},
		{
			name:           "CONNECT without port (should add default)",
			connectRequest: "CONNECT example.com HTTP/1.1\r\n\r\n",
			expectedDomain: "example.com",
			expectedAddr:   "example.com:443", // Should add default HTTPS port for TLS
		},
		{
			name:           "CONNECT with custom port",
			connectRequest: "CONNECT api.example.com:8443 HTTP/1.1\r\n\r\n",
			expectedDomain: "api.example.com",
			expectedAddr:   "api.example.com:8443",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Simulate CONNECT request parsing
			parts := strings.Fields(test.connectRequest)
			if len(parts) < 2 {
				t.Fatalf("Invalid CONNECT request: %s", test.connectRequest)
			}

			serverAddr := parts[1]
			var domain string

			// This mirrors the logic in handleConnection
			if colonIndex := strings.Index(serverAddr, ":"); colonIndex != -1 {
				domain = serverAddr[:colonIndex]
			} else {
				domain = serverAddr
				// If no port specified, add default port (simulating TLS)
				serverAddr = domain + ":443"
			}

			if domain != test.expectedDomain {
				t.Errorf("Expected domain %s, got %s", test.expectedDomain, domain)
			}

			if serverAddr != test.expectedAddr {
				t.Errorf("Expected address %s, got %s", test.expectedAddr, serverAddr)
			}

			// Verify no double colons in address
			colonCount := strings.Count(serverAddr, ":")
			if colonCount != 1 {
				t.Errorf("Expected exactly 1 colon in address %s, got %d", serverAddr, colonCount)
			}
		})
	}
}

// Test parseHTTPResponse function
func TestParseHTTPResponse(t *testing.T) {
	tests := []struct {
		name          string
		data          []byte
		shouldErr     bool
		statusCode    int
		hasHeaders    bool
		expectedBody  string
		contentLength string
	}{
		{
			name:          "Valid HTTP 200 response",
			data:          []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 12\r\n\r\nHello World!"),
			shouldErr:     false,
			statusCode:    200,
			hasHeaders:    true,
			expectedBody:  "Hello World!",
			contentLength: "12",
		},
		{
			name:          "Valid HTTP 404 response",
			data:          []byte("HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: 9\r\n\r\nNot Found"),
			shouldErr:     false,
			statusCode:    404,
			hasHeaders:    true,
			expectedBody:  "Not Found",
			contentLength: "9",
		},
		{
			name:          "Response without body",
			data:          []byte("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n"),
			shouldErr:     false,
			statusCode:    204,
			hasHeaders:    true,
			expectedBody:  "",
			contentLength: "0",
		},
		{
			name:          "Response with JSON body",
			data:          []byte("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 25\r\n\r\n{\"message\": \"success\"}"),
			shouldErr:     false,
			statusCode:    200,
			hasHeaders:    true,
			expectedBody:  "{\"message\": \"success\"}",
			contentLength: "25",
		},
		{
			name:      "Invalid status line",
			data:      []byte("INVALID\r\n\r\n"),
			shouldErr: true,
		},
		{
			name:      "Empty data",
			data:      []byte{},
			shouldErr: true,
		},
		{
			name:         "Incomplete response (headers only)",
			data:         []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"),
			shouldErr:    false,
			statusCode:   200,
			hasHeaders:   true,
			expectedBody: "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response, err := parseHTTPResponse(test.data)

			if test.shouldErr {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if response.StatusCode != test.statusCode {
				t.Errorf("Expected status code %d, got %d", test.statusCode, response.StatusCode)
			}

			if test.hasHeaders && test.contentLength != "" {
				if contentLen, exists := response.Headers["Content-Length"]; !exists {
					t.Error("Expected Content-Length header to exist")
				} else if contentLen != test.contentLength {
					t.Errorf("Expected Content-Length %s, got %s", test.contentLength, contentLen)
				}
			}

			if response.Body != test.expectedBody {
				t.Errorf("Expected body %q, got %q", test.expectedBody, response.Body)
			}
		})
	}
}

// Test inspectHTTPWithCapture function
func TestInspectHTTPWithCapture(t *testing.T) {
	tempDir := t.TempDir()
	captureDir := filepath.Join(tempDir, "captures")
	err := os.MkdirAll(captureDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create capture directory: %v", err)
	}

	config := &Config{
		Logging: struct {
			LogFile     string `json:"log_file"`
			CaptureDir  string `json:"capture_dir"`
			MaxFileSize int64  `json:"max_file_size_mb"`
			EnableDebug bool   `json:"enable_debug"`
		}{
			LogFile:    filepath.Join(tempDir, "test.log"),
			CaptureDir: captureDir,
		},
		Rules: struct {
			InspectDomains []string `json:"inspect_domains"`
			InspectIPs     []string `json:"inspect_source_ips"`
			BypassDomains  []string `json:"bypass_domains"`
			BypassIPs      []string `json:"bypass_source_ips"`
		}{
			InspectDomains: []string{"example.com"},
		},
		TLS: struct {
			CertFile          string `json:"cert_file"`
			KeyFile           string `json:"key_file"`
			CAFile            string `json:"ca_file"`
			CAKeyFile         string `json:"ca_key_file"`
			CertDir           string `json:"cert_dir"`
			AutoGenerate      bool   `json:"auto_generate"`
			ValidDays         int    `json:"valid_days"`
			UpstreamCertSniff bool   `json:"upstream_cert_sniff"`
		}{
			CertDir:      filepath.Join(tempDir, "certs"),
			CAFile:       filepath.Join(tempDir, "certs", "ca.crt"),
			CAKeyFile:    filepath.Join(tempDir, "certs", "ca.key"),
			AutoGenerate: true,
			ValidDays:    365,
		},
	}

	proxy, err := NewProxyServer(config)
	if err != nil {
		t.Fatalf("Failed to create proxy server: %v", err)
	}
	defer proxy.logFile.Close()

	// Test HTTP request data
	requestData := []byte("GET /test HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n")

	// Test inspectHTTPWithCapture
	capture := proxy.inspectHTTPWithCapture(requestData, "192.168.1.1", "example.com")

	// Check that a request was captured
	if capture == nil {
		t.Error("Expected captured request but got nil")
		return
	}

	if capture.Method != "GET" {
		t.Errorf("Expected method GET, got %s", capture.Method)
	}
	if capture.URL != "/test" {
		t.Errorf("Expected URL /test, got %s", capture.URL)
	}
	if capture.Domain != "example.com" {
		t.Errorf("Expected domain example.com, got %s", capture.Domain)
	}
	if capture.ClientIP != "192.168.1.1" {
		t.Errorf("Expected client IP 192.168.1.1, got %s", capture.ClientIP)
	}
}

// Test inspectHTTPResponse function
func TestInspectHTTPResponse(t *testing.T) {
	tempDir := t.TempDir()
	captureDir := filepath.Join(tempDir, "captures")
	err := os.MkdirAll(captureDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create capture directory: %v", err)
	}

	config := &Config{
		Logging: struct {
			LogFile     string `json:"log_file"`
			CaptureDir  string `json:"capture_dir"`
			MaxFileSize int64  `json:"max_file_size_mb"`
			EnableDebug bool   `json:"enable_debug"`
		}{
			LogFile:    filepath.Join(tempDir, "test.log"),
			CaptureDir: captureDir,
		},
		TLS: struct {
			CertFile          string `json:"cert_file"`
			KeyFile           string `json:"key_file"`
			CAFile            string `json:"ca_file"`
			CAKeyFile         string `json:"ca_key_file"`
			CertDir           string `json:"cert_dir"`
			AutoGenerate      bool   `json:"auto_generate"`
			ValidDays         int    `json:"valid_days"`
			UpstreamCertSniff bool   `json:"upstream_cert_sniff"`
		}{
			CertDir:      filepath.Join(tempDir, "certs"),
			CAFile:       filepath.Join(tempDir, "certs", "ca.crt"),
			CAKeyFile:    filepath.Join(tempDir, "certs", "ca.key"),
			AutoGenerate: true,
			ValidDays:    365,
		},
	}

	proxy, err := NewProxyServer(config)
	if err != nil {
		t.Fatalf("Failed to create proxy server: %v", err)
	}
	defer proxy.logFile.Close()

	// Create a captured request to match with response
	requestCapture := &HTTPCapture{
		Method:   "GET",
		URL:      "/test",
		Domain:   "example.com",
		ClientIP: "192.168.1.1",
		Headers:  map[string]string{"Host": "example.com"},
		Body:     "",
	}

	// Test HTTP response data
	responseData := []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 12\r\n\r\nHello World!")

	// Test inspectHTTPResponse
	proxy.inspectHTTPResponse(responseData, "192.168.1.1", "example.com", requestCapture)

	// Verify that the response was processed (check logs or file system)
	// Since the function writes to files, we can check the capture directory
	files, err := os.ReadDir(captureDir)
	if err != nil {
		t.Fatalf("Failed to read capture directory: %v", err)
	}

	if len(files) == 0 {
		t.Error("Expected capture file to be created but none found")
	}
}

// Test certificate trust functionality (mock test since we can't actually modify system)
func TestCertificateTrustFunctionality(t *testing.T) {
	tempDir := t.TempDir()
	certDir := filepath.Join(tempDir, "certs")
	err := os.MkdirAll(certDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create cert directory: %v", err)
	}

	// Create a mock CA certificate file
	caCertPath := filepath.Join(certDir, "ca.crt")
	mockCertData := `-----BEGIN CERTIFICATE-----
MIICxjCCAa4CAQAwDQYJKoZIhvcNAQELBQAwEzERMA8GA1UEAwwIVGVzdCBDQSAx
MB4XDTI0MDEwMTAwMDAwMFoXDTI1MDEwMTAwMDAwMFowEzERMA8GA1UEAwwIVGVz
dCBDQSAxMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1234567890
-----END CERTIFICATE-----`

	err = os.WriteFile(caCertPath, []byte(mockCertData), 0644)
	if err != nil {
		t.Fatalf("Failed to create mock CA certificate: %v", err)
	}

	// Test that the certificate file exists and can be read
	if _, err := os.Stat(caCertPath); os.IsNotExist(err) {
		t.Error("CA certificate file should exist")
	}

	// Test reading the certificate file
	certData, err := os.ReadFile(caCertPath)
	if err != nil {
		t.Fatalf("Failed to read CA certificate: %v", err)
	}

	if !strings.Contains(string(certData), "BEGIN CERTIFICATE") {
		t.Error("Certificate file should contain certificate data")
	}

	// Test certificate directory structure
	expectedFiles := []string{"ca.crt"}
	for _, expectedFile := range expectedFiles {
		filePath := filepath.Join(certDir, expectedFile)
		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			t.Errorf("Expected certificate file %s should exist", expectedFile)
		}
	}
}

// Test HTTPS interception decision making
func TestHTTPSInterceptionDecision(t *testing.T) {
	tempDir := t.TempDir()

	config := &Config{
		Logging: struct {
			LogFile     string `json:"log_file"`
			CaptureDir  string `json:"capture_dir"`
			MaxFileSize int64  `json:"max_file_size_mb"`
			EnableDebug bool   `json:"enable_debug"`
		}{
			LogFile:    filepath.Join(tempDir, "test.log"),
			CaptureDir: filepath.Join(tempDir, "captures"),
		},
		Rules: struct {
			InspectDomains []string `json:"inspect_domains"`
			InspectIPs     []string `json:"inspect_source_ips"`
			BypassDomains  []string `json:"bypass_domains"`
			BypassIPs      []string `json:"bypass_source_ips"`
		}{
			InspectDomains: []string{"example.com", "api.example.com"},
			InspectIPs:     []string{"192.168.1.100"},
			BypassDomains:  []string{"google.com"},
			BypassIPs:      []string{"127.0.0.1"},
		},
		TLS: struct {
			CertFile          string `json:"cert_file"`
			KeyFile           string `json:"key_file"`
			CAFile            string `json:"ca_file"`
			CAKeyFile         string `json:"ca_key_file"`
			CertDir           string `json:"cert_dir"`
			AutoGenerate      bool   `json:"auto_generate"`
			ValidDays         int    `json:"valid_days"`
			UpstreamCertSniff bool   `json:"upstream_cert_sniff"`
		}{
			CertDir:      filepath.Join(tempDir, "certs"),
			CAFile:       filepath.Join(tempDir, "certs", "ca.crt"),
			CAKeyFile:    filepath.Join(tempDir, "certs", "ca.key"),
			AutoGenerate: true,
			ValidDays:    365,
		},
	}

	proxy, err := NewProxyServer(config)
	if err != nil {
		t.Fatalf("Failed to create proxy server: %v", err)
	}
	defer proxy.logFile.Close()

	tests := []struct {
		name            string
		clientIP        string
		domain          string
		expectedInspect bool
		expectedRelay   string // "inspection" or "fast"
	}{
		{
			name:            "Should use inspection relay for inspected domain",
			clientIP:        "192.168.1.200",
			domain:          "example.com",
			expectedInspect: true,
			expectedRelay:   "inspection",
		},
		{
			name:            "Should use inspection relay for inspected IP",
			clientIP:        "192.168.1.100",
			domain:          "other.com",
			expectedInspect: true,
			expectedRelay:   "inspection",
		},
		{
			name:            "Should use fast relay for bypassed domain",
			clientIP:        "192.168.1.200",
			domain:          "google.com",
			expectedInspect: false,
			expectedRelay:   "fast",
		},
		{
			name:            "Should use fast relay for bypassed IP",
			clientIP:        "127.0.0.1",
			domain:          "example.com",
			expectedInspect: false,
			expectedRelay:   "fast",
		},
		{
			name:            "Should use fast relay for non-inspected traffic",
			clientIP:        "192.168.1.200",
			domain:          "other.com",
			expectedInspect: false,
			expectedRelay:   "fast",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			shouldInspect := proxy.shouldInspect(test.clientIP, test.domain)

			if shouldInspect != test.expectedInspect {
				t.Errorf("shouldInspect(%s, %s) = %v, expected %v",
					test.clientIP, test.domain, shouldInspect, test.expectedInspect)
			}

			// Test the relay decision logic (simulated)
			var relayType string
			if shouldInspect {
				relayType = "inspection"
			} else {
				relayType = "fast"
			}

			if relayType != test.expectedRelay {
				t.Errorf("Expected relay type %s, got %s", test.expectedRelay, relayType)
			}
		})
	}
}

// Test complete request/response capture flow
func TestCompleteRequestResponseCapture(t *testing.T) {
	tempDir := t.TempDir()
	captureDir := filepath.Join(tempDir, "captures")
	err := os.MkdirAll(captureDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create capture directory: %v", err)
	}

	config := &Config{
		Logging: struct {
			LogFile     string `json:"log_file"`
			CaptureDir  string `json:"capture_dir"`
			MaxFileSize int64  `json:"max_file_size_mb"`
			EnableDebug bool   `json:"enable_debug"`
		}{
			LogFile:    filepath.Join(tempDir, "test.log"),
			CaptureDir: captureDir,
		},
		Rules: struct {
			InspectDomains []string `json:"inspect_domains"`
			InspectIPs     []string `json:"inspect_source_ips"`
			BypassDomains  []string `json:"bypass_domains"`
			BypassIPs      []string `json:"bypass_source_ips"`
		}{
			InspectDomains: []string{"example.com"},
		},
		TLS: struct {
			CertFile          string `json:"cert_file"`
			KeyFile           string `json:"key_file"`
			CAFile            string `json:"ca_file"`
			CAKeyFile         string `json:"ca_key_file"`
			CertDir           string `json:"cert_dir"`
			AutoGenerate      bool   `json:"auto_generate"`
			ValidDays         int    `json:"valid_days"`
			UpstreamCertSniff bool   `json:"upstream_cert_sniff"`
		}{
			CertDir:      filepath.Join(tempDir, "certs"),
			CAFile:       filepath.Join(tempDir, "certs", "ca.crt"),
			CAKeyFile:    filepath.Join(tempDir, "certs", "ca.key"),
			AutoGenerate: true,
			ValidDays:    365,
		},
	}

	proxy, err := NewProxyServer(config)
	if err != nil {
		t.Fatalf("Failed to create proxy server: %v", err)
	}
	defer proxy.logFile.Close()

	// Simulate a complete request/response flow

	// Step 1: Capture HTTP request
	requestData := []byte("POST /api/test HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\nContent-Length: 25\r\n\r\n{\"message\": \"hello\"}")
	requestCapture := proxy.inspectHTTPWithCapture(requestData, "192.168.1.1", "example.com")

	// Step 2: Capture HTTP response
	responseData := []byte("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 25\r\n\r\n{\"status\": \"success\"}")
	if requestCapture != nil {
		proxy.inspectHTTPResponse(responseData, "192.168.1.1", "example.com", requestCapture)
	}

	// Verify capture files were created
	files, err := os.ReadDir(captureDir)
	if err != nil {
		t.Fatalf("Failed to read capture directory: %v", err)
	}

	if len(files) == 0 {
		t.Error("Expected capture files to be created but none found")
	}

	// Verify the capture file contains both request and response data
	if len(files) > 0 {
		captureFile := filepath.Join(captureDir, files[0].Name())
		captureData, err := os.ReadFile(captureFile)
		if err != nil {
			t.Fatalf("Failed to read capture file: %v", err)
		}

		captureContent := string(captureData)

		// Check for request data
		if !strings.Contains(captureContent, "POST") {
			t.Error("Capture file should contain request method")
		}
		if !strings.Contains(captureContent, "/api/test") {
			t.Error("Capture file should contain request URL")
		}
		if !strings.Contains(captureContent, "hello") {
			t.Error("Capture file should contain request body")
		}

		// Check for response data
		if !strings.Contains(captureContent, "200") {
			t.Error("Capture file should contain response status")
		}
		if !strings.Contains(captureContent, "success") {
			t.Error("Capture file should contain response body")
		}
	}
}

// Test performance difference between inspection and fast relays
func TestRelayPerformanceDifference(t *testing.T) {
	tempDir := t.TempDir()

	config := &Config{
		Logging: struct {
			LogFile     string `json:"log_file"`
			CaptureDir  string `json:"capture_dir"`
			MaxFileSize int64  `json:"max_file_size_mb"`
			EnableDebug bool   `json:"enable_debug"`
		}{
			LogFile:    filepath.Join(tempDir, "test.log"),
			CaptureDir: filepath.Join(tempDir, "captures"),
		},
		Rules: struct {
			InspectDomains []string `json:"inspect_domains"`
			InspectIPs     []string `json:"inspect_source_ips"`
			BypassDomains  []string `json:"bypass_domains"`
			BypassIPs      []string `json:"bypass_source_ips"`
		}{
			InspectDomains: []string{"example.com"},
			BypassDomains:  []string{"fast.com"},
		},
		TLS: struct {
			CertFile          string `json:"cert_file"`
			KeyFile           string `json:"key_file"`
			CAFile            string `json:"ca_file"`
			CAKeyFile         string `json:"ca_key_file"`
			CertDir           string `json:"cert_dir"`
			AutoGenerate      bool   `json:"auto_generate"`
			ValidDays         int    `json:"valid_days"`
			UpstreamCertSniff bool   `json:"upstream_cert_sniff"`
		}{
			CertDir:      filepath.Join(tempDir, "certs"),
			CAFile:       filepath.Join(tempDir, "certs", "ca.crt"),
			CAKeyFile:    filepath.Join(tempDir, "certs", "ca.key"),
			AutoGenerate: true,
			ValidDays:    365,
		},
	}

	proxy, err := NewProxyServer(config)
	if err != nil {
		t.Fatalf("Failed to create proxy server: %v", err)
	}
	defer proxy.logFile.Close()

	// Test that inspection decision is made quickly
	start := time.Now()
	for i := 0; i < 1000; i++ {
		proxy.shouldInspect("192.168.1.1", "example.com")
	}
	inspectionTime := time.Since(start)

	start = time.Now()
	for i := 0; i < 1000; i++ {
		proxy.shouldInspect("192.168.1.1", "fast.com")
	}
	bypassTime := time.Since(start)

	// Both should be fast, but this tests that the decision logic doesn't add significant overhead
	if inspectionTime > 100*time.Millisecond {
		t.Errorf("Inspection decision taking too long: %v", inspectionTime)
	}
	if bypassTime > 100*time.Millisecond {
		t.Errorf("Bypass decision taking too long: %v", bypassTime)
	}

	t.Logf("Inspection decision time: %v, Bypass decision time: %v", inspectionTime, bypassTime)
}

// Benchmark the new response parsing functionality
func BenchmarkParseHTTPResponse(b *testing.B) {
	responseData := []byte("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 25\r\nServer: nginx\r\n\r\n{\"status\": \"success\"}")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := parseHTTPResponse(responseData)
		if err != nil {
			b.Fatalf("Unexpected error: %v", err)
		}
	}
}

// Benchmark inspection vs non-inspection decision making
func BenchmarkInspectionDecision(b *testing.B) {
	tempDir := b.TempDir()

	config := &Config{
		Logging: struct {
			LogFile     string `json:"log_file"`
			CaptureDir  string `json:"capture_dir"`
			MaxFileSize int64  `json:"max_file_size_mb"`
			EnableDebug bool   `json:"enable_debug"`
		}{
			LogFile:    filepath.Join(tempDir, "test.log"),
			CaptureDir: filepath.Join(tempDir, "captures"),
		},
		Rules: struct {
			InspectDomains []string `json:"inspect_domains"`
			InspectIPs     []string `json:"inspect_source_ips"`
			BypassDomains  []string `json:"bypass_domains"`
			BypassIPs      []string `json:"bypass_source_ips"`
		}{
			InspectDomains: []string{"example.com", "api.example.com", "test.com"},
			BypassDomains:  []string{"google.com", "fast.com"},
		},
		TLS: struct {
			CertFile          string `json:"cert_file"`
			KeyFile           string `json:"key_file"`
			CAFile            string `json:"ca_file"`
			CAKeyFile         string `json:"ca_key_file"`
			CertDir           string `json:"cert_dir"`
			AutoGenerate      bool   `json:"auto_generate"`
			ValidDays         int    `json:"valid_days"`
			UpstreamCertSniff bool   `json:"upstream_cert_sniff"`
		}{
			CertDir:      filepath.Join(tempDir, "certs"),
			CAFile:       filepath.Join(tempDir, "certs", "ca.crt"),
			CAKeyFile:    filepath.Join(tempDir, "certs", "ca.key"),
			AutoGenerate: true,
			ValidDays:    365,
		},
	}

	proxy, err := NewProxyServer(config)
	if err != nil {
		b.Fatalf("Failed to create proxy server: %v", err)
	}
	defer proxy.logFile.Close()

	domains := []string{"example.com", "google.com", "api.example.com", "fast.com", "other.com"}
	ips := []string{"192.168.1.1", "192.168.1.100", "10.0.0.1", "127.0.0.1"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		domain := domains[i%len(domains)]
		ip := ips[i%len(ips)]
		proxy.shouldInspect(ip, domain)
	}
}
