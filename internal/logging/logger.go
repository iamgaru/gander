package logging

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// LogLevel represents different logging levels
type LogLevel int

const (
	LevelError LogLevel = iota
	LevelWarn
	LevelInfo
	LevelDebug
)

// String returns the string representation of the log level
func (l LogLevel) String() string {
	switch l {
	case LevelError:
		return "ERROR"
	case LevelWarn:
		return "WARN"
	case LevelInfo:
		return "INFO"
	case LevelDebug:
		return "DEBUG"
	default:
		return "UNKNOWN"
	}
}

// Logger handles multi-destination logging with different verbosity levels
type Logger struct {
	fileLogger    *log.Logger
	consoleLogger *log.Logger
	logFile       *os.File
	enableDebug   bool
	logLevel      LogLevel
	mutex         sync.RWMutex
}

// Config holds logger configuration
type Config struct {
	LogFile      string   // Path to log file
	EnableDebug  bool     // Enable debug logging
	LogLevel     LogLevel // Minimum log level
	ConsoleLevel LogLevel // Maximum level to show on console (LevelInfo for minimal output)
}

// NewLogger creates a new logger instance
func NewLogger(config Config) (*Logger, error) {
	logger := &Logger{
		enableDebug: config.EnableDebug,
		logLevel:    config.LogLevel,
	}

	// Setup console logger (stdout)
	logger.consoleLogger = log.New(os.Stdout, "", 0) // No timestamp prefix for console

	// Setup file logger if log file is specified
	if config.LogFile != "" {
		// Create log directory if it doesn't exist
		logDir := filepath.Dir(config.LogFile)
		if err := os.MkdirAll(logDir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create log directory: %w", err)
		}

		// Open log file
		file, err := os.OpenFile(config.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return nil, fmt.Errorf("failed to open log file: %w", err)
		}

		logger.logFile = file
		logger.fileLogger = log.New(file, "", log.LstdFlags|log.Lmicroseconds)

		// Redirect standard log package to file
		log.SetOutput(file)
		log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	}

	return logger, nil
}

// Close closes the log file
func (l *Logger) Close() error {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	if l.logFile != nil {
		return l.logFile.Close()
	}
	return nil
}

// SetOutput redirects standard log package output
func (l *Logger) SetOutput(w io.Writer) {
	log.SetOutput(w)
}

// logToFile writes a message to the log file
func (l *Logger) logToFile(level LogLevel, format string, args ...interface{}) {
	if l.fileLogger != nil && level <= l.logLevel {
		message := fmt.Sprintf(format, args...)
		l.fileLogger.Printf("[%s] %s", level.String(), message)
	}
}

// logToConsole writes a message to the console (minimal output)
func (l *Logger) logToConsole(level LogLevel, format string, args ...interface{}) {
	// Only show ERROR and INFO on console for minimal output
	if level <= LevelInfo {
		timestamp := time.Now().Format("15:04:05")
		message := fmt.Sprintf(format, args...)
		l.consoleLogger.Printf("[%s] %s", timestamp, message)
	}
}

// Error logs an error message (shown on both console and file)
func (l *Logger) Error(format string, args ...interface{}) {
	l.mutex.RLock()
	defer l.mutex.RUnlock()

	l.logToFile(LevelError, format, args...)
	l.logToConsole(LevelError, format, args...)
}

// Warn logs a warning message (file only unless debug enabled)
func (l *Logger) Warn(format string, args ...interface{}) {
	l.mutex.RLock()
	defer l.mutex.RUnlock()

	l.logToFile(LevelWarn, format, args...)
	if l.enableDebug {
		l.logToConsole(LevelWarn, format, args...)
	}
}

// Info logs an info message (shown on console and file)
func (l *Logger) Info(format string, args ...interface{}) {
	l.mutex.RLock()
	defer l.mutex.RUnlock()

	l.logToFile(LevelInfo, format, args...)
	l.logToConsole(LevelInfo, format, args...)
}

// Debug logs a debug message (file only, and only if debug enabled)
func (l *Logger) Debug(format string, args ...interface{}) {
	l.mutex.RLock()
	defer l.mutex.RUnlock()

	if l.enableDebug {
		l.logToFile(LevelDebug, format, args...)
		// Debug messages are never shown on console to keep it clean
	}
}

// Request logs a request (verbose, file only)
func (l *Logger) Request(format string, args ...interface{}) {
	l.mutex.RLock()
	defer l.mutex.RUnlock()

	if l.enableDebug {
		l.logToFile(LevelDebug, "[REQUEST] "+format, args...)
	}
}

// Response logs a response (verbose, file only)
func (l *Logger) Response(format string, args ...interface{}) {
	l.mutex.RLock()
	defer l.mutex.RUnlock()

	if l.enableDebug {
		l.logToFile(LevelDebug, "[RESPONSE] "+format, args...)
	}
}

// Stats logs statistics (console for essential stats, file for detailed)
func (l *Logger) Stats(essential bool, format string, args ...interface{}) {
	l.mutex.RLock()
	defer l.mutex.RUnlock()

	l.logToFile(LevelInfo, "[STATS] "+format, args...)
	if essential {
		l.logToConsole(LevelInfo, format, args...)
	}
}

// Global logger instance
var globalLogger *Logger

// InitGlobalLogger initializes the global logger
func InitGlobalLogger(config Config) error {
	logger, err := NewLogger(config)
	if err != nil {
		return err
	}
	globalLogger = logger
	return nil
}

// GetGlobalLogger returns the global logger instance
func GetGlobalLogger() *Logger {
	return globalLogger
}

// CloseGlobalLogger closes the global logger
func CloseGlobalLogger() error {
	if globalLogger != nil {
		return globalLogger.Close()
	}
	return nil
}

// Convenience functions for global logger
func Error(format string, args ...interface{}) {
	if globalLogger != nil {
		globalLogger.Error(format, args...)
	}
}

func Warn(format string, args ...interface{}) {
	if globalLogger != nil {
		globalLogger.Warn(format, args...)
	}
}

func Info(format string, args ...interface{}) {
	if globalLogger != nil {
		globalLogger.Info(format, args...)
	}
}

func Debug(format string, args ...interface{}) {
	if globalLogger != nil {
		globalLogger.Debug(format, args...)
	}
}

func Request(format string, args ...interface{}) {
	if globalLogger != nil {
		globalLogger.Request(format, args...)
	}
}

func Response(format string, args ...interface{}) {
	if globalLogger != nil {
		globalLogger.Response(format, args...)
	}
}

func Stats(essential bool, format string, args ...interface{}) {
	if globalLogger != nil {
		globalLogger.Stats(essential, format, args...)
	}
}
