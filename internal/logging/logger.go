package logging

import (
	"fmt"
	"io"
	"log"
	"os"
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
	consoleLevel LogLevel
	fileLogger   *log.Logger
	consoleLog   *log.Logger
	fileOutput   io.Writer
}

// NewLogger creates a new logger with the specified console level and file output
func NewLogger(consoleLevelStr string, logFile string) (*Logger, error) {
	level := parseLogLevel(consoleLevelStr)
	
	logger := &Logger{
		consoleLevel: level,
		consoleLog:   log.New(os.Stdout, "", 0), // No default prefix for console
	}
	
	// Setup file logging if specified
	if logFile != "" {
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
	if l.fileLogger != nil {
		l.fileLogger.Printf("CRITICAL: %s", msg)
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
	if l.fileLogger != nil {
		l.fileLogger.Printf("INFO: %s", msg)
	}
}

// Status logs periodic status messages (shown on minimal, normal, and debug)
func (l *Logger) Status(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	timestamp := time.Now().Format("15:04:05")
	
	// Always show status messages on console (even minimal level)
	l.consoleLog.Printf("[%s] STATUS: %s", timestamp, msg)
	
	// Also log to file if available
	if l.fileLogger != nil {
		l.fileLogger.Printf("STATUS: %s", msg)
	}
}

// Config logs configuration change messages (shown on minimal, normal, and debug)
func (l *Logger) Config(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	timestamp := time.Now().Format("15:04:05")
	
	// Always show config messages on console (even minimal level)
	l.consoleLog.Printf("[%s] CONFIG: %s", timestamp, msg)
	
	// Also log to file if available
	if l.fileLogger != nil {
		l.fileLogger.Printf("CONFIG: %s", msg)
	}
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
	if l.fileLogger != nil {
		l.fileLogger.Printf("DEBUG: %s", msg)
	}
}

// Verbose logs verbose messages (file-only, never on console)
func (l *Logger) Verbose(format string, args ...interface{}) {
	if l.fileLogger != nil {
		msg := fmt.Sprintf(format, args...)
		l.fileLogger.Printf("VERBOSE: %s", msg)
	}
}

// Startup logs startup messages (always shown)
func (l *Logger) Startup(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	timestamp := time.Now().Format("15:04:05")
	
	// Always show startup messages
	l.consoleLog.Printf("[%s] STARTUP: %s", timestamp, msg)
	
	// Also log to file if available
	if l.fileLogger != nil {
		l.fileLogger.Printf("STARTUP: %s", msg)
	}
}

// Shutdown logs shutdown messages (always shown)
func (l *Logger) Shutdown(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	timestamp := time.Now().Format("15:04:05")
	
	// Always show shutdown messages
	l.consoleLog.Printf("[%s] SHUTDOWN: %s", timestamp, msg)
	
	// Also log to file if available
	if l.fileLogger != nil {
		l.fileLogger.Printf("SHUTDOWN: %s", msg)
	}
}

// SetLevel updates the console logging level
func (l *Logger) SetLevel(consoleLevelStr string) {
	l.consoleLevel = parseLogLevel(consoleLevelStr)
}

// Close closes the file logger if open
func (l *Logger) Close() error {
	if l.fileOutput != nil {
		if closer, ok := l.fileOutput.(io.Closer); ok {
			return closer.Close()
		}
	}
	return nil
}