package main

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Test HTTP capture saving functionality
func TestSaveCapture(t *testing.T) {
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

	// Create a test capture
	capture := &HTTPCapture{
		Timestamp: time.Now(),
		ClientIP:  "192.168.1.100",
		Domain:    "test.example.com",
		Method:    "GET",
		URL:       "/test",
		Headers: map[string]string{
			"Host":       "test.example.com",
			"User-Agent": "test-agent",
		},
		Body: "test body",
	}

	// Save the capture
	proxy.saveCapture(capture)

	// Check that capture directory was created and file exists
	captureDir := proxy.config.Logging.CaptureDir
	files, err := os.ReadDir(captureDir)
	if err != nil {
		t.Fatalf("Failed to read capture directory: %v", err)
	}

	if len(files) == 0 {
		t.Error("Expected at least one capture file, got none")
	}

	// Check that captured requests counter was incremented
	stats := proxy.GetStats()
	if stats.CapturedRequests != 1 {
		t.Errorf("Expected 1 captured request, got %d", stats.CapturedRequests)
	}
}

// Test inspect HTTP with various HTTP methods
func TestInspectHTTP(t *testing.T) {
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

	tests := []struct {
		name          string
		data          []byte
		shouldCapture bool
	}{
		{
			name:          "GET request",
			data:          []byte("GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			shouldCapture: true,
		},
		{
			name:          "POST request",
			data:          []byte("POST /api HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			shouldCapture: true,
		},
		{
			name:          "PUT request",
			data:          []byte("PUT /resource HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			shouldCapture: true,
		},
		{
			name:          "DELETE request",
			data:          []byte("DELETE /resource HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			shouldCapture: true,
		},
		{
			name:          "HEAD request",
			data:          []byte("HEAD /test HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			shouldCapture: true,
		},
		{
			name:          "OPTIONS request",
			data:          []byte("OPTIONS /test HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			shouldCapture: true,
		},
		{
			name:          "Unknown method",
			data:          []byte("UNKNOWN /test HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			shouldCapture: false,
		},
		{
			name:          "Non-HTTP data",
			data:          []byte{0x16, 0x03, 0x01, 0x00, 0x05},
			shouldCapture: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			initialRequests := proxy.GetStats().CapturedRequests

			proxy.inspectHTTP(test.data, "192.168.1.100", "example.com")

			finalRequests := proxy.GetStats().CapturedRequests
			captured := finalRequests > initialRequests

			if captured != test.shouldCapture {
				t.Errorf("Expected shouldCapture=%v, got captured=%v", test.shouldCapture, captured)
			}
		})
	}
}

// Test connection logging
func TestLogConnection(t *testing.T) {
	tempDir := t.TempDir()
	logFile := filepath.Join(tempDir, "test.log")

	config := &Config{
		Logging: struct {
			LogFile     string `json:"log_file"`
			CaptureDir  string `json:"capture_dir"`
			MaxFileSize int64  `json:"max_file_size_mb"`
			EnableDebug bool   `json:"enable_debug"`
		}{
			LogFile:    logFile,
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

	// Create connection info
	info := &ConnectionInfo{
		ClientIP:   "192.168.1.100",
		ServerAddr: "example.com:443",
		Domain:     "example.com",
		Protocol:   "HTTPS",
		StartTime:  time.Now().Add(-2 * time.Second),
		BytesRead:  1024,
		BytesWrite: 2048,
		Inspected:  true,
		Captured:   true,
	}

	// Log the connection
	proxy.logConnection(info)

	// Verify log file exists and has content
	if _, err := os.Stat(logFile); os.IsNotExist(err) {
		t.Error("Log file was not created")
	}

	content, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("Failed to read log file: %v", err)
	}

	logContent := string(content)

	// Check that log contains expected information
	expectedStrings := []string{
		"192.168.1.100",
		"example.com:443",
		"example.com",
		"HTTPS",
		"inspected=true",
		"captured=true",
	}

	for _, expected := range expectedStrings {
		if !contains(logContent, expected) {
			t.Errorf("Expected log to contain '%s', but it didn't. Log content: %s", expected, logContent)
		}
	}
}

// Test edge cases for domain/IP rules
func TestRuleEdgeCases(t *testing.T) {
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
			InspectDomains: []string{"EXAMPLE.COM", "Test.Com"}, // Mixed case
			InspectIPs:     []string{"192.168.1.100"},
			BypassDomains:  []string{"GOOGLE.COM"},
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
		{"192.168.1.100", "example.com", true, "Should inspect: case insensitive domain match"},
		{"192.168.1.100", "EXAMPLE.COM", true, "Should inspect: case insensitive domain match (uppercase)"},
		{"192.168.1.200", "test.com", true, "Should inspect: case insensitive domain match"},
		{"127.0.0.1", "example.com", false, "Should not inspect: bypass IP takes precedence"},
		{"192.168.1.200", "google.com", false, "Should not inspect: case insensitive bypass domain"},
		{"192.168.1.200", "GOOGLE.COM", false, "Should not inspect: case insensitive bypass domain (uppercase)"},
		{"", "example.com", true, "Should inspect: empty IP with domain match"},
		{"192.168.1.100", "", true, "Should inspect: IP match with empty domain"},
		{"", "", false, "Should not inspect: both empty"},
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

// Test buffer pool functionality indirectly
func TestBufferPool(t *testing.T) {
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
			BufferSize: 1024, // Custom buffer size
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

	// Test that buffer pool is initialized
	if proxy.bufferPool == nil {
		t.Error("Buffer pool should be initialized")
	}

	// Test buffer pool functionality
	buffer := *proxy.bufferPool.Get().(*[]byte)
	if len(buffer) != 1024 {
		t.Errorf("Expected buffer size 1024, got %d", len(buffer))
	}

	// Return buffer to pool
	proxy.bufferPool.Put(&buffer)

	// Get another buffer (should be the same one due to pooling)
	buffer2 := *proxy.bufferPool.Get().(*[]byte)
	if len(buffer2) != 1024 {
		t.Errorf("Expected buffer size 1024, got %d", len(buffer2))
	}
}

// Helper function to check if string contains substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || (len(s) > len(substr) &&
		(s[:len(substr)] == substr || s[len(s)-len(substr):] == substr ||
			func() bool {
				for i := 1; i <= len(s)-len(substr); i++ {
					if s[i:i+len(substr)] == substr {
						return true
					}
				}
				return false
			}())))
}

// Benchmark rule checking performance
func BenchmarkRuleChecking(b *testing.B) {
	tempDir := b.TempDir()

	// Create a config with many rules
	inspectDomains := make([]string, 1000)
	inspectIPs := make([]string, 1000)
	for i := 0; i < 1000; i++ {
		inspectDomains[i] = fmt.Sprintf("domain%d.com", i)
		inspectIPs[i] = fmt.Sprintf("192.168.%d.%d", i/256, i%256)
	}

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
			InspectDomains: inspectDomains,
			InspectIPs:     inspectIPs,
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
		proxy.shouldInspect("192.168.100.100", "domain500.com")
	}
}
