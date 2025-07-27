package capture

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNewCaptureManager(t *testing.T) {
	tempDir := t.TempDir()
	manager := NewCaptureManager(tempDir, false)

	if manager == nil {
		t.Fatal("Expected capture manager to be created, got nil")
	}

	if manager.captureDir != tempDir {
		t.Errorf("Expected capture dir %s, got %s", tempDir, manager.captureDir)
	}

	if manager.enableDebug != false {
		t.Error("Expected debug to be disabled")
	}

	if manager.config == nil {
		t.Error("Expected config to be initialized")
	}
}

func TestDefaultCaptureConfig(t *testing.T) {
	config := DefaultCaptureConfig()

	if config.MaxBodySize != 1024*1024 {
		t.Errorf("Expected max body size 1MB, got %d", config.MaxBodySize)
	}

	if config.MaxPendingRequests != 1000 {
		t.Errorf("Expected max pending requests 1000, got %d", config.MaxPendingRequests)
	}

	if !config.IncludeBody {
		t.Error("Expected include body to be true")
	}

	if !config.SanitizeHeaders {
		t.Error("Expected sanitize headers to be true")
	}
}

func TestCaptureHTTPRequest(t *testing.T) {
	tempDir := t.TempDir()
	manager := NewCaptureManager(tempDir, false)
	err := manager.Initialize()
	if err != nil {
		t.Fatalf("Failed to initialize capture manager: %v", err)
	}

	// Create a test HTTP request
	req, err := http.NewRequest("GET", "http://example.com/test?param=value", strings.NewReader("test body"))
	if err != nil {
		t.Fatalf("Failed to create test request: %v", err)
	}
	req.Header.Set("User-Agent", "test-agent")
	req.Header.Set("Authorization", "Bearer token")

	clientIP := "192.168.1.100"

	// Capture the request
	err = manager.CaptureHTTPRequest(req, clientIP)
	if err != nil {
		t.Fatalf("Failed to capture HTTP request: %v", err)
	}

	// Check stats
	stats := manager.GetStats()
	if stats.RequestsCaptured != 1 {
		t.Errorf("Expected 1 request captured, got %d", stats.RequestsCaptured)
	}

	if stats.PendingRequests != 1 {
		t.Errorf("Expected 1 pending request, got %d", stats.PendingRequests)
	}
}

func TestCaptureHTTPResponse(t *testing.T) {
	tempDir := t.TempDir()
	manager := NewCaptureManager(tempDir, false)
	
	// Use flat organization for this test
	config := DefaultCaptureConfig()
	config.OrganizationScheme = "flat"
	manager.SetConfig(config)
	
	err := manager.Initialize()
	if err != nil {
		t.Fatalf("Failed to initialize capture manager: %v", err)
	}

	// First capture a request to correlate with
	req, err := http.NewRequest("GET", "http://example.com/test", nil)
	if err != nil {
		t.Fatalf("Failed to create test request: %v", err)
	}

	clientIP := "192.168.1.100"
	err = manager.CaptureHTTPRequest(req, clientIP)
	if err != nil {
		t.Fatalf("Failed to capture HTTP request: %v", err)
	}

	// Add a small delay to ensure the request is processed
	time.Sleep(10 * time.Millisecond)

	// Create a test HTTP response
	resp := &http.Response{
		StatusCode: 200,
		Status:     "200 OK",
		Header:     make(http.Header),
		Request:    req,
	}
	resp.Header.Set("Content-Type", "application/json")
	resp.Header.Set("Server", "nginx/1.18.0")

	// Capture the response
	err = manager.CaptureHTTPResponse(resp, clientIP)
	if err != nil {
		t.Fatalf("Failed to capture HTTP response: %v", err)
	}

	// Check stats
	stats := manager.GetStats()
	if stats.ResponsesCaptured != 1 {
		t.Errorf("Expected 1 response captured, got %d", stats.ResponsesCaptured)
	}

	if stats.PairsCaptured != 1 {
		t.Errorf("Expected 1 pair captured, got %d", stats.PairsCaptured)
	}

	// Check that a file was created
	files, err := os.ReadDir(tempDir)
	if err != nil {
		t.Fatalf("Failed to read capture directory: %v", err)
	}

	if len(files) != 1 {
		t.Errorf("Expected 1 capture file, got %d", len(files))
	}

	// Verify the file is valid JSON
	if len(files) > 0 {
		filePath := filepath.Join(tempDir, files[0].Name())
		data, err := os.ReadFile(filePath)
		if err != nil {
			t.Fatalf("Failed to read capture file: %v", err)
		}

		var capture HTTPCapture
		err = json.Unmarshal(data, &capture)
		if err != nil {
			t.Fatalf("Failed to parse capture JSON: %v", err)
		}

		if capture.Method != "GET" {
			t.Errorf("Expected method GET, got %s", capture.Method)
		}

		if capture.Domain != "example.com" {
			t.Errorf("Expected domain example.com, got %s", capture.Domain)
		}

		if capture.Response == nil {
			t.Error("Expected response to be included in capture")
		}

		if capture.Response.StatusCode != 200 {
			t.Errorf("Expected status code 200, got %d", capture.Response.StatusCode)
		}
	}
}

func TestHeaderExtraction(t *testing.T) {
	manager := NewCaptureManager("", false)

	headers := http.Header{}
	headers.Set("Content-Type", "application/json")
	headers.Set("Authorization", "Bearer token")
	headers.Set("User-Agent", "test-agent")
	headers.Set("X-Custom", "custom-value")

	extracted := manager.extractHeaders(headers)

	// Should include most headers
	if extracted["Content-Type"] != "application/json" {
		t.Errorf("Expected Content-Type to be preserved")
	}

	if extracted["User-Agent"] != "test-agent" {
		t.Errorf("Expected User-Agent to be preserved")
	}

	if extracted["X-Custom"] != "custom-value" {
		t.Errorf("Expected X-Custom to be preserved")
	}

	// Authorization should be excluded by default config
	if _, exists := extracted["Authorization"]; exists && manager.config.SanitizeHeaders {
		t.Error("Expected Authorization header to be excluded with default config")
	}
}

func TestCaptureStats(t *testing.T) {
	stats := NewCaptureStats()
	if stats == nil {
		t.Fatal("Expected capture stats to be created, got nil")
	}

	// Test initial values
	initialStats := stats.GetStats()
	if initialStats.RequestsCaptured != 0 {
		t.Errorf("Expected 0 requests captured initially, got %d", initialStats.RequestsCaptured)
	}

	// Test stat operations
	stats.IncrementRequestsCaptured()
	stats.IncrementResponsesCaptured()
	stats.IncrementPairsCaptured()
	stats.AddBytesProcessed(1024)

	updatedStats := stats.GetStats()
	if updatedStats.RequestsCaptured != 1 {
		t.Errorf("Expected 1 request captured, got %d", updatedStats.RequestsCaptured)
	}

	if updatedStats.ResponsesCaptured != 1 {
		t.Errorf("Expected 1 response captured, got %d", updatedStats.ResponsesCaptured)
	}

	if updatedStats.PairsCaptured != 1 {
		t.Errorf("Expected 1 pair captured, got %d", updatedStats.PairsCaptured)
	}

	if updatedStats.TotalBytesProcessed != 1024 {
		t.Errorf("Expected 1024 bytes processed, got %d", updatedStats.TotalBytesProcessed)
	}
}

func TestFilenameGeneration(t *testing.T) {
	manager := NewCaptureManager("", false)

	capture := &HTTPCapture{
		Timestamp: time.Date(2024, 6, 22, 15, 30, 45, 123000000, time.UTC),
		ClientIP:  "192.168.1.100",
		Domain:    "example.com",
		Method:    "GET",
		Path:      "/api/test",
	}

	filename := manager.generateFilename(capture)

	// Should contain timestamp, IP, domain, method, path
	if !strings.Contains(filename, "2024-06-22") {
		t.Error("Filename should contain date")
	}

	if !strings.Contains(filename, "15-30-45") {
		t.Error("Filename should contain time")
	}

	if !strings.Contains(filename, "192.168.1.100") {
		t.Error("Filename should contain client IP")
	}

	if !strings.Contains(filename, "example.com") {
		t.Error("Filename should contain domain")
	}

	if !strings.Contains(filename, "get") {
		t.Error("Filename should contain method (lowercase)")
	}

	if !strings.HasSuffix(filename, ".json") {
		t.Error("Filename should end with .json")
	}
}

func TestCaptureConfiguration(t *testing.T) {
	tempDir := t.TempDir()
	manager := NewCaptureManager(tempDir, true) // Enable debug

	// Test setting custom config
	customConfig := &CaptureConfig{
		MaxBodySize:        512,
		MaxPendingRequests: 50,
		IncludeBody:        false,
		SanitizeHeaders:    false,
		EnableMetadata:     false,
	}

	manager.SetConfig(customConfig)

	if manager.config.MaxBodySize != 512 {
		t.Errorf("Expected max body size 512, got %d", manager.config.MaxBodySize)
	}

	if manager.config.IncludeBody != false {
		t.Error("Expected include body to be false")
	}

	if manager.config.SanitizeHeaders != false {
		t.Error("Expected sanitize headers to be false")
	}
}

// Benchmark tests
func BenchmarkCaptureRequest(b *testing.B) {
	tempDir := b.TempDir()
	manager := NewCaptureManager(tempDir, false)
	_ = manager.Initialize()

	req, _ := http.NewRequest("GET", "http://example.com/benchmark", nil)
	req.Header.Set("User-Agent", "benchmark-test")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = manager.CaptureHTTPRequest(req, "192.168.1.100")
	}
}

func BenchmarkStatsAccess(b *testing.B) {
	manager := NewCaptureManager("", false)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			manager.GetStats()
		}
	})
}

func BenchmarkHeaderExtraction(b *testing.B) {
	manager := NewCaptureManager("", false)

	headers := http.Header{}
	headers.Set("Content-Type", "application/json")
	headers.Set("User-Agent", "test-agent")
	headers.Set("Authorization", "Bearer token")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		manager.extractHeaders(headers)
	}
}

// TestDomainBasedCapture tests the domain-based capture directory structure
func TestDomainBasedCapture(t *testing.T) {
	// Create temporary directory for testing
	testDir := t.TempDir()

	// Create capture manager with domain-based organization
	manager := NewCaptureManager(testDir, true)
	config := DefaultCaptureConfig()
	config.OrganizationScheme = "domain"
	manager.SetConfig(config)

	if err := manager.Initialize(); err != nil {
		t.Fatalf("Failed to initialize capture manager: %v", err)
	}

	// Create test HTTP request
	req, err := http.NewRequest("GET", "https://example.com/api/test", nil)
	if err != nil {
		t.Fatalf("Failed to create test request: %v", err)
	}
	req.Host = "example.com"

	// Capture the request
	if err := manager.CaptureHTTPRequest(req, "127.0.0.1:12345"); err != nil {
		t.Fatalf("Failed to capture HTTP request: %v", err)
	}

	// Create a dummy response to complete the request/response pair
	resp := &http.Response{
		StatusCode: 200,
		Status:     "200 OK",
		Header:     make(http.Header),
		Request:    req,
	}
	resp.Header.Set("Content-Type", "application/json")

	// Capture the response to trigger the complete capture save
	if err := manager.CaptureHTTPResponse(resp, "127.0.0.1:12345"); err != nil {
		t.Fatalf("Failed to capture HTTP response: %v", err)
	}

	// Verify domain-based directory structure was created
	expectedDomainDir := filepath.Join(testDir, "example.com")
	if _, err := os.Stat(expectedDomainDir); os.IsNotExist(err) {
		t.Errorf("Expected domain directory %s to be created", expectedDomainDir)
	}

	// Verify date directory was created
	dateStr := time.Now().Format("2006-01-02")
	expectedDateDir := filepath.Join(expectedDomainDir, dateStr)
	if _, err := os.Stat(expectedDateDir); os.IsNotExist(err) {
		t.Errorf("Expected date directory %s to be created", expectedDateDir)
	}

	// Verify responses directory was created (since we captured a complete request/response pair)
	expectedResponsesDir := filepath.Join(expectedDateDir, "responses")
	if _, err := os.Stat(expectedResponsesDir); os.IsNotExist(err) {
		t.Errorf("Expected responses directory %s to be created", expectedResponsesDir)
	}

	// Verify metadata file was created
	expectedMetadataFile := filepath.Join(expectedDomainDir, "metadata.json")
	if _, err := os.Stat(expectedMetadataFile); os.IsNotExist(err) {
		t.Errorf("Expected metadata file %s to be created", expectedMetadataFile)
	}

	// Verify capture file was created with correct naming
	files, err := os.ReadDir(expectedResponsesDir)
	if err != nil {
		t.Fatalf("Failed to read responses directory: %v", err)
	}

	if len(files) != 1 {
		t.Errorf("Expected 1 capture file, got %d", len(files))
	}

	// Check filename format: should be 001_resp_GET_api_test.json
	filename := files[0].Name()
	if !strings.HasPrefix(filename, "001_resp_GET_") {
		t.Errorf("Expected filename to start with '001_resp_GET_', got %s", filename)
	}
}

// TestDomainBasedCaptureWithResponse tests request/response pairing
func TestDomainBasedCaptureWithResponse(t *testing.T) {
	// Create temporary directory for testing
	testDir := t.TempDir()

	// Create capture manager with domain-based organization
	manager := NewCaptureManager(testDir, true)
	config := DefaultCaptureConfig()
	config.OrganizationScheme = "domain"
	manager.SetConfig(config)

	if err := manager.Initialize(); err != nil {
		t.Fatalf("Failed to initialize capture manager: %v", err)
	}

	// Create test HTTP request
	req, err := http.NewRequest("POST", "https://api.github.com/user", nil)
	if err != nil {
		t.Fatalf("Failed to create test request: %v", err)
	}
	req.Host = "api.github.com"

	// Capture the request
	if err := manager.CaptureHTTPRequest(req, "127.0.0.1:54321"); err != nil {
		t.Fatalf("Failed to capture HTTP request: %v", err)
	}

	// Create test HTTP response
	resp := &http.Response{
		StatusCode: 200,
		Status:     "200 OK",
		Header:     make(http.Header),
		Request:    req,
	}
	resp.Header.Set("Content-Type", "application/json")

	// Capture the response
	if err := manager.CaptureHTTPResponse(resp, "127.0.0.1:54321"); err != nil {
		t.Fatalf("Failed to capture HTTP response: %v", err)
	}

	// Verify api.github.com domain directory was created
	expectedDomainDir := filepath.Join(testDir, "api.github.com")
	if _, err := os.Stat(expectedDomainDir); os.IsNotExist(err) {
		t.Errorf("Expected domain directory %s to be created", expectedDomainDir)
	}

	// Verify both requests and responses directories exist
	dateStr := time.Now().Format("2006-01-02")
	expectedResponsesDir := filepath.Join(expectedDomainDir, dateStr, "responses")

	if _, err := os.Stat(expectedResponsesDir); os.IsNotExist(err) {
		t.Errorf("Expected responses directory %s to be created", expectedResponsesDir)
	}

	// Check that response file was created  
	responseFiles, err := os.ReadDir(expectedResponsesDir)
	if err != nil {
		t.Fatalf("Failed to read responses directory: %v", err)
	}

	if len(responseFiles) == 0 {
		t.Error("Expected at least 1 response file")
	}
}
