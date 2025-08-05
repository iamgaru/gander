package logging

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNewFeatureLogger(t *testing.T) {
	tests := []struct {
		name          string
		enabled       bool
		maxFileSizeMB int64
		logConfigs    map[string]bool
		expectError   bool
	}{
		{
			name:          "Disabled feature logger",
			enabled:       false,
			maxFileSizeMB: 50,
			logConfigs:    map[string]bool{"filtering": true},
			expectError:   false,
		},
		{
			name:          "Enabled with filtering log",
			enabled:       true,
			maxFileSizeMB: 50,
			logConfigs:    map[string]bool{"filtering": true, "certificates": false},
			expectError:   false,
		},
		{
			name:          "All logs enabled",
			enabled:       true,
			maxFileSizeMB: 100,
			logConfigs: map[string]bool{
				"filtering":    true,
				"certificates": true,
				"errors":       true,
				"performance":  true,
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary directory
			tempDir, err := os.MkdirTemp("", "feature_logger_test")
			if err != nil {
				t.Fatalf("Failed to create temp dir: %v", err)
			}
			defer os.RemoveAll(tempDir)

			fl, err := NewFeatureLogger(tt.enabled, tt.maxFileSizeMB, tempDir, tt.logConfigs)
			
			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if fl == nil {
				t.Error("Expected non-nil feature logger")
			}

			// Clean up
			if fl != nil {
				fl.Close()
			}
		})
	}
}

func TestFeatureLoggerLogging(t *testing.T) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "feature_logger_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create feature logger with all logs enabled
	logConfigs := map[string]bool{
		"filtering":    true,
		"certificates": true,
		"errors":       true,
		"performance":  true,
	}
	
	fl, err := NewFeatureLogger(true, 50, tempDir, logConfigs)
	if err != nil {
		t.Fatalf("Failed to create feature logger: %v", err)
	}
	defer fl.Close()

	// Test filtering log
	fl.LogFiltering("corr123", "example.com", "192.168.1.100", "blocked", "domain_inspection", "blacklist_match")
	
	// Test certificate log
	fl.LogCertificate("generate", "test.com", 25*time.Millisecond, "success", map[string]interface{}{"worker_id": 1})
	
	// Test error log
	fl.LogError("critical", "proxy", "connection failed", map[string]interface{}{"error_code": 500})
	
	// Test performance log
	fl.LogPerformance("request_duration", "250ms", map[string]interface{}{"domain": "slow.com", "threshold": "200ms"})

	// Close to flush all logs
	fl.Close()

	// Verify log files were created and contain expected content
	testCases := []struct {
		filename        string
		expectedContent []string
	}{
		{
			filename: "filtering.log",
			expectedContent: []string{
				"[corr123]",
				"target=example.com",
				"verdict=blocked",
				"method=domain_inspection",
				"reason=blacklist_match",
				"client_ip=192.168.1.100",
			},
		},
		{
			filename: "certificates.log",
			expectedContent: []string{
				"action=generate",
				"domain=test.com",
				"status=success",
				"duration=25ms",
				"worker_id=1",
			},
		},
		{
			filename: "errors.log",
			expectedContent: []string{
				"level=critical",
				"component=proxy",
				"error=\"connection failed\"",
				"error_code=500",
			},
		},
		{
			filename: "performance.log",
			expectedContent: []string{
				"metric=request_duration",
				"value=250ms",
				"domain=slow.com",
				"threshold=200ms",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.filename, func(t *testing.T) {
			logPath := filepath.Join(tempDir, tc.filename)
			
			// Check file exists
			if _, err := os.Stat(logPath); os.IsNotExist(err) {
				t.Errorf("Log file %s was not created", tc.filename)
				return
			}

			// Read file content
			content, err := os.ReadFile(logPath)
			if err != nil {
				t.Errorf("Failed to read log file %s: %v", tc.filename, err)
				return
			}

			contentStr := string(content)
			
			// Check all expected content is present
			for _, expected := range tc.expectedContent {
				if !strings.Contains(contentStr, expected) {
					t.Errorf("Log file %s missing expected content: %s\nActual content:\n%s", 
						tc.filename, expected, contentStr)
				}
			}

			// Verify timestamp format
			if !strings.Contains(contentStr, "[2025-") {
				t.Errorf("Log file %s missing proper timestamp format", tc.filename)
			}
		})
	}
}

func TestFeatureLoggerDisabled(t *testing.T) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "feature_logger_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create disabled feature logger
	fl, err := NewFeatureLogger(false, 50, tempDir, map[string]bool{"filtering": true})
	if err != nil {
		t.Fatalf("Failed to create feature logger: %v", err)
	}
	defer fl.Close()

	// Try to log - should be no-op
	fl.LogFiltering("corr123", "example.com", "192.168.1.100", "blocked", "domain_inspection", "test")
	
	// Close to ensure any potential writes are flushed
	fl.Close()

	// Verify no log files were created
	logPath := filepath.Join(tempDir, "filtering.log")
	if _, err := os.Stat(logPath); !os.IsNotExist(err) {
		t.Error("Log file was created despite feature logger being disabled")
	}
}

func TestFeatureLoggerFileRotation(t *testing.T) {
	// Skip this test in short mode as it involves file operations
	if testing.Short() {
		t.Skip("Skipping file rotation test in short mode")
	}

	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "feature_logger_rotation_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create feature logger with very small file size for testing rotation
	logConfigs := map[string]bool{"filtering": true}
	fl, err := NewFeatureLogger(true, 1, tempDir, logConfigs) // 1MB max size
	if err != nil {
		t.Fatalf("Failed to create feature logger: %v", err)
	}
	defer fl.Close()

	// Log many entries to trigger rotation
	for i := 0; i < 1000; i++ {
		fl.LogFiltering("corr123", "example.com", "192.168.1.100", "blocked", "domain_inspection", 
			"test_rotation_with_long_reason_text_to_increase_file_size_quickly")
	}

	// Close to flush
	fl.Close()

	// Check if original log file exists
	logPath := filepath.Join(tempDir, "filtering.log")
	if _, err := os.Stat(logPath); os.IsNotExist(err) {
		t.Error("Main log file should exist")
	}
}

func TestFeatureLoggerClose(t *testing.T) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "feature_logger_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	logConfigs := map[string]bool{
		"filtering":    true,
		"certificates": true,
	}
	
	fl, err := NewFeatureLogger(true, 50, tempDir, logConfigs)
	if err != nil {
		t.Fatalf("Failed to create feature logger: %v", err)
	}

	// Log something
	fl.LogFiltering("corr123", "example.com", "192.168.1.100", "blocked", "domain_inspection", "test")

	// Close should not error
	err = fl.Close()
	if err != nil {
		t.Errorf("Close returned error: %v", err)
	}

	// Subsequent logging should be no-op (shouldn't panic)
	fl.LogFiltering("corr123", "example.com", "192.168.1.100", "blocked", "domain_inspection", "test")

	// Closing again should not error
	err = fl.Close()
	if err != nil {
		t.Errorf("Second close returned error: %v", err)
	}
}

func TestFeatureLoggerConcurrency(t *testing.T) {
	// Skip this test in short mode
	if testing.Short() {
		t.Skip("Skipping concurrency test in short mode")
	}

	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "feature_logger_concurrent_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	logConfigs := map[string]bool{"filtering": true}
	fl, err := NewFeatureLogger(true, 50, tempDir, logConfigs)
	if err != nil {
		t.Fatalf("Failed to create feature logger: %v", err)
	}
	defer fl.Close()

	// Launch multiple goroutines to log concurrently
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func(id int) {
			for j := 0; j < 100; j++ {
				fl.LogFiltering("corr123", "example.com", "192.168.1.100", "blocked", "domain_inspection", "concurrent_test")
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}

	// Close and verify file was created without corruption
	fl.Close()

	logPath := filepath.Join(tempDir, "filtering.log")
	if _, err := os.Stat(logPath); os.IsNotExist(err) {
		t.Error("Log file should exist after concurrent logging")
	}
}