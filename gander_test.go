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
