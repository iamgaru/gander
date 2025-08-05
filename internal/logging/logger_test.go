package logging

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewLogger(t *testing.T) {
	tests := []struct {
		name         string
		consoleLevel string
		logFile      string
		expectError  bool
	}{
		{
			name:         "Valid minimal level",
			consoleLevel: "minimal",
			logFile:      "",
			expectError:  false,
		},
		{
			name:         "Valid normal level",
			consoleLevel: "normal",
			logFile:      "",
			expectError:  false,
		},
		{
			name:         "Valid debug level",
			consoleLevel: "debug",
			logFile:      "",
			expectError:  false,
		},
		{
			name:         "Invalid level defaults to normal",
			consoleLevel: "invalid",
			logFile:      "",
			expectError:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var logFile string
			if tt.logFile != "" {
				// Create temporary file
				tempDir, err := os.MkdirTemp("", "logger_test")
				if err != nil {
					t.Fatalf("Failed to create temp dir: %v", err)
				}
				defer os.RemoveAll(tempDir)
				logFile = filepath.Join(tempDir, "test.log")
			}

			logger, err := NewLogger(tt.consoleLevel, logFile)
			
			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if logger == nil {
				t.Error("Expected non-nil logger")
			}

			// Clean up
			if logger != nil {
				logger.Close()
			}
		})
	}
}

func TestLoggerWithFile(t *testing.T) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "logger_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	logFile := filepath.Join(tempDir, "test.log")
	logger, err := NewLogger("normal", logFile)
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer logger.Close()

	// Test different log methods
	logger.Critical("Critical message")
	logger.Info("Info message")
	logger.Debug("Debug message")
	logger.Verbose("Verbose message")

	// Close to flush
	logger.Close()

	// Read log file
	content, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("Failed to read log file: %v", err)
	}

	contentStr := string(content)
	
	// Check expected content
	expectedMessages := []string{
		"CRITICAL: Critical message",
		"INFO: Info message", 
		"DEBUG: Debug message",
		"VERBOSE: Verbose message",
	}

	for _, expected := range expectedMessages {
		if !strings.Contains(contentStr, expected) {
			t.Errorf("Log file missing expected message: %s\nActual content:\n%s", expected, contentStr)
		}
	}
}

func TestLoggerFeatureLoggerIntegration(t *testing.T) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "logger_integration_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create main logger
	logFile := filepath.Join(tempDir, "main.log")
	logger, err := NewLogger("normal", logFile)
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer logger.Close()

	// Create feature logger
	logConfigs := map[string]bool{"errors": true}
	featureLogger, err := NewFeatureLogger(true, 50, tempDir, logConfigs)
	if err != nil {
		t.Fatalf("Failed to create feature logger: %v", err)
	}

	// Set feature logger
	logger.SetFeatureLogger(featureLogger)

	// Verify integration
	if logger.GetFeatureLogger() != featureLogger {
		t.Error("Feature logger not set correctly")
	}

	// Test critical message - should go to both main log and errors.log
	logger.Critical("Test critical error")

	// Close to flush
	logger.Close()

	// Check main log file
	mainContent, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("Failed to read main log file: %v", err)
	}
	if !strings.Contains(string(mainContent), "CRITICAL: Test critical error") {
		t.Error("Main log file missing critical message")
	}

	// Check errors.log file
	errorsLogPath := filepath.Join(tempDir, "errors.log")
	errorsContent, err := os.ReadFile(errorsLogPath)
	if err != nil {
		t.Fatalf("Failed to read errors log file: %v", err)
	}
	errorsStr := string(errorsContent)
	
	expectedInErrors := []string{
		"level=critical",
		"component=proxy",
		"error=\"Test critical error\"",
	}

	for _, expected := range expectedInErrors {
		if !strings.Contains(errorsStr, expected) {
			t.Errorf("Errors log missing expected content: %s\nActual content:\n%s", expected, errorsStr)
		}
	}
}

func TestLoggerSetLevel(t *testing.T) {
	logger, err := NewLogger("minimal", "")
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer logger.Close()

	// Test level changes
	logger.SetLevel("debug")
	logger.SetLevel("normal")
	logger.SetLevel("minimal")
	logger.SetLevel("invalid") // Should not crash
}

func TestLoggerStructuredLogging(t *testing.T) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "structured_logger_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	logFile := filepath.Join(tempDir, "structured.log")
	logger, err := NewLogger("debug", logFile)
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer logger.Close()

	// Test structured logging methods
	logger.InfoStructured("corr123", "Test message", "key1", "value1", "key2", "value2")
	logger.DebugStructured("corr456", "Debug message", "debug_key", "debug_value")
	logger.VerboseStructured("corr789", "Verbose message", "verbose_key", "verbose_value")

	// Close to flush
	logger.Close()

	// Read log file
	content, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("Failed to read log file: %v", err)
	}

	contentStr := string(content)
	
	// Check structured format
	expectedStructured := []string{
		"INFO: Test message correlation_id=corr123 key1=value1 key2=value2",
		"DEBUG: Debug message correlation_id=corr456 debug_key=debug_value",
		"VERBOSE: Verbose message correlation_id=corr789 verbose_key=verbose_value",
	}

	for _, expected := range expectedStructured {
		if !strings.Contains(contentStr, expected) {
			t.Errorf("Log file missing structured content: %s\nActual content:\n%s", expected, contentStr)
		}
	}
}

func TestGenerateCorrelationID(t *testing.T) {
	// Test correlation ID generation
	id1 := GenerateCorrelationID()
	id2 := GenerateCorrelationID()

	if id1 == id2 {
		t.Error("Correlation IDs should be unique")
	}

	if len(id1) == 0 {
		t.Error("Correlation ID should not be empty")
	}

	// Should be hex encoded (16 characters for 8 bytes)
	if len(id1) != 16 {
		t.Errorf("Expected correlation ID length of 16, got %d", len(id1))
	}
}

func TestLoggerClose(t *testing.T) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "logger_close_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	logFile := filepath.Join(tempDir, "test.log")
	logger, err := NewLogger("normal", logFile)
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	// Add feature logger
	featureLogger, err := NewFeatureLogger(true, 50, tempDir, map[string]bool{"filtering": true})
	if err != nil {
		t.Fatalf("Failed to create feature logger: %v", err)
	}
	logger.SetFeatureLogger(featureLogger)

	// Log some messages
	logger.Info("Test message")
	
	// Close should not error and should close both loggers
	err = logger.Close()
	if err != nil {
		t.Errorf("Close returned error: %v", err)
	}

	// Verify log file was created
	if _, err := os.Stat(logFile); os.IsNotExist(err) {
		t.Error("Log file should exist after close")
	}
}