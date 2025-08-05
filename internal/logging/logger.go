package logging

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// LogLevel represents the different console logging levels
type LogLevel int

const (
	Minimal LogLevel = iota
	Normal
	Debug
)

// Logger provides structured logging with level control
type Logger struct {
	consoleLevel  LogLevel
	fileLogger    *log.Logger
	consoleLog    *log.Logger
	fileOutput    io.Writer
	logFilePath   string
	maxFileSize   int64 // in bytes
	featureLogger FeatureLogger
}

// NewLogger creates a new logger with the specified console level and file output
func NewLogger(consoleLevelStr string, logFile string) (*Logger, error) {
	level := parseLogLevel(consoleLevelStr)
	
	logger := &Logger{
		consoleLevel: level,
		consoleLog:   log.New(os.Stdout, "", 0), // No default prefix for console
		logFilePath:  logFile,
		maxFileSize:  100 * 1024 * 1024, // Default 100MB
	}
	
	// Setup file logging if specified
	if logFile != "" {
		// Ensure directory exists
		dir := filepath.Dir(logFile)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create log directory: %w", err)
		}
		
		file, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			return nil, fmt.Errorf("failed to open log file: %w", err)
		}
		
		logger.fileOutput = file
		logger.fileLogger = log.New(file, "", log.LstdFlags|log.Lmicroseconds)
	}
	
	return logger, nil
}

// parseLogLevel converts string to LogLevel
func parseLogLevel(level string) LogLevel {
	switch level {
	case "minimal":
		return Minimal
	case "normal":
		return Normal
	case "debug":
		return Debug
	default:
		return Normal
	}
}

// Critical logs critical messages (always shown on console)
func (l *Logger) Critical(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	timestamp := time.Now().Format("15:04:05")
	
	// Always show critical messages on console
	l.consoleLog.Printf("[%s] CRITICAL: %s", timestamp, msg)
	
	// Also log to file if available
	l.rotatableWrite(fmt.Sprintf("CRITICAL: %s", msg))
	
	// Log to errors.log via feature logger
	if l.featureLogger != nil {
		l.featureLogger.LogError("critical", "proxy", msg, nil)
	}
}

// Info logs informational messages (shown on normal and debug levels)
func (l *Logger) Info(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	timestamp := time.Now().Format("15:04:05")
	
	// Show on console for normal and debug levels
	if l.consoleLevel >= Normal {
		l.consoleLog.Printf("[%s] %s", timestamp, msg)
	}
	
	// Always log to file if available
	l.rotatableWrite(fmt.Sprintf("INFO: %s", msg))
}

// Status logs periodic status messages (shown on minimal, normal, and debug)
func (l *Logger) Status(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	timestamp := time.Now().Format("15:04:05")
	
	// Always show status messages on console (even minimal level)
	l.consoleLog.Printf("[%s] STATUS: %s", timestamp, msg)
	
	// Also log to file if available
	l.rotatableWrite(fmt.Sprintf("STATUS: %s", msg))
}

// Config logs configuration change messages (shown on minimal, normal, and debug)
func (l *Logger) Config(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	timestamp := time.Now().Format("15:04:05")
	
	// Always show config messages on console (even minimal level)
	l.consoleLog.Printf("[%s] CONFIG: %s", timestamp, msg)
	
	// Also log to file if available
	l.rotatableWrite(fmt.Sprintf("CONFIG: %s", msg))
}

// Debug logs debug messages (only shown on debug level)
func (l *Logger) Debug(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	
	// Only show on console for debug level
	if l.consoleLevel >= Debug {
		timestamp := time.Now().Format("15:04:05")
		l.consoleLog.Printf("[%s] DEBUG: %s", timestamp, msg)
	}
	
	// Always log to file if available
	l.rotatableWrite(fmt.Sprintf("DEBUG: %s", msg))
}

// Verbose logs verbose messages (file-only, never on console)
func (l *Logger) Verbose(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	l.rotatableWrite(fmt.Sprintf("VERBOSE: %s", msg))
}

// Startup logs startup messages (always shown)
func (l *Logger) Startup(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	timestamp := time.Now().Format("15:04:05")
	
	// Always show startup messages
	l.consoleLog.Printf("[%s] STARTUP: %s", timestamp, msg)
	
	// Also log to file if available
	l.rotatableWrite(fmt.Sprintf("STARTUP: %s", msg))
}

// Shutdown logs shutdown messages (always shown)
func (l *Logger) Shutdown(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	timestamp := time.Now().Format("15:04:05")
	
	// Always show shutdown messages
	l.consoleLog.Printf("[%s] SHUTDOWN: %s", timestamp, msg)
	
	// Also log to file if available
	l.rotatableWrite(fmt.Sprintf("SHUTDOWN: %s", msg))
}

// SetLevel updates the console logging level
func (l *Logger) SetLevel(consoleLevelStr string) {
	l.consoleLevel = parseLogLevel(consoleLevelStr)
}

// SetFeatureLogger sets the feature logger for this logger instance
func (l *Logger) SetFeatureLogger(featureLogger FeatureLogger) {
	l.featureLogger = featureLogger
}

// GetFeatureLogger returns the feature logger instance
func (l *Logger) GetFeatureLogger() FeatureLogger {
	return l.featureLogger
}

// Close closes the file logger if open
func (l *Logger) Close() error {
	var lastErr error
	
	// Close feature logger if available
	if l.featureLogger != nil {
		if err := l.featureLogger.Close(); err != nil {
			lastErr = err
		}
	}
	
	// Close main file logger
	if l.fileOutput != nil {
		if closer, ok := l.fileOutput.(io.Closer); ok {
			if err := closer.Close(); err != nil {
				lastErr = err
			}
		}
	}
	
	return lastErr
}

// GenerateCorrelationID generates a unique correlation ID for request tracking
func GenerateCorrelationID() string {
	bytes := make([]byte, 8)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// formatStructured formats a message with key-value pairs
func formatStructured(msg string, kvPairs ...string) string {
	if len(kvPairs) == 0 {
		return msg
	}
	
	var parts []string
	parts = append(parts, msg)
	
	for i := 0; i < len(kvPairs); i += 2 {
		if i+1 < len(kvPairs) {
			parts = append(parts, fmt.Sprintf("%s=%s", kvPairs[i], kvPairs[i+1]))
		}
	}
	
	return strings.Join(parts, " ")
}

// LogWithCorrelation logs a message with correlation ID and optional key-value pairs
func (l *Logger) LogWithCorrelation(level string, correlationID string, msg string, kvPairs ...string) {
	// Add correlation ID to key-value pairs
	allKVs := []string{"correlation_id", correlationID}
	allKVs = append(allKVs, kvPairs...)
	
	structuredMsg := formatStructured(msg, allKVs...)
	
	// Always log to file with full structured format using rotatable write
	l.rotatableWrite(fmt.Sprintf("%s: %s", level, structuredMsg))
}

// InfoStructured logs structured info messages
func (l *Logger) InfoStructured(correlationID string, msg string, kvPairs ...string) {
	l.LogWithCorrelation("INFO", correlationID, msg, kvPairs...)
}

// DebugStructured logs structured debug messages  
func (l *Logger) DebugStructured(correlationID string, msg string, kvPairs ...string) {
	l.LogWithCorrelation("DEBUG", correlationID, msg, kvPairs...)
}

// VerboseStructured logs structured verbose messages (file-only)
func (l *Logger) VerboseStructured(correlationID string, msg string, kvPairs ...string) {
	l.LogWithCorrelation("VERBOSE", correlationID, msg, kvPairs...)
}

// SetMaxFileSize sets the maximum file size for log rotation
func (l *Logger) SetMaxFileSize(sizeInMB int64) {
	l.maxFileSize = sizeInMB * 1024 * 1024
}

// checkAndRotateLog checks if the log file needs rotation and performs it if necessary
func (l *Logger) checkAndRotateLog() error {
	if l.logFilePath == "" || l.fileOutput == nil {
		return nil
	}

	// Get current file size
	fileInfo, err := os.Stat(l.logFilePath)
	if err != nil {
		return err
	}

	// Check if rotation is needed
	if fileInfo.Size() < l.maxFileSize {
		return nil
	}

	// Close current file
	if closer, ok := l.fileOutput.(io.Closer); ok {
		closer.Close()
	}

	// Create rotation filename with timestamp
	timestamp := time.Now().Format("2006-01-02_15-04-05")
	dir := filepath.Dir(l.logFilePath)
	base := filepath.Base(l.logFilePath)
	ext := filepath.Ext(base)
	name := strings.TrimSuffix(base, ext)
	
	rotatedFile := filepath.Join(dir, fmt.Sprintf("%s_%s%s", name, timestamp, ext))

	// Rename current file to rotated filename
	if err := os.Rename(l.logFilePath, rotatedFile); err != nil {
		return fmt.Errorf("failed to rotate log file: %w", err)
	}

	// Create new log file
	file, err := os.OpenFile(l.logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		return fmt.Errorf("failed to create new log file after rotation: %w", err)
	}

	// Update logger
	l.fileOutput = file
	l.fileLogger = log.New(file, "", log.LstdFlags|log.Lmicroseconds)

	return nil
}

// rotatableWrite writes to the log file and checks for rotation
func (l *Logger) rotatableWrite(message string) {
	if l.fileLogger != nil {
		// Check for rotation before writing
		if err := l.checkAndRotateLog(); err != nil {
			// If rotation fails, still try to write to existing file
			fmt.Fprintf(os.Stderr, "Log rotation failed: %v\n", err)
		}
		l.fileLogger.Print(message)
	}
}