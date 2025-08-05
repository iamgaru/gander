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

// FeatureLogger interface for feature-specific logging
type FeatureLogger interface {
	LogFiltering(correlationID, target, clientIP, verdict, method, reason string)
	LogCertificate(action, domain string, duration time.Duration, status string, extra map[string]interface{})
	LogError(level, component, error string, extra map[string]interface{})
	LogPerformance(metric string, value interface{}, extra map[string]interface{})
	Close() error
}


// DefaultFeatureLogger implements FeatureLogger interface
type DefaultFeatureLogger struct {
	enabled     bool
	maxFileSize int64
	loggers     map[string]*featureFileLogger
	loggerMutex sync.RWMutex
	logDir      string
	logConfigs  map[string]bool // simple enabled/disabled per log
}

// featureFileLogger wraps file operations for individual feature logs
type featureFileLogger struct {
	name        string
	filePath    string
	fileOutput  io.WriteCloser
	logger      *log.Logger
	maxFileSize int64
	mutex       sync.Mutex
}

// NewFeatureLogger creates a new feature logger with the specified configuration
func NewFeatureLogger(enabled bool, maxFileSizeMB int64, logDir string, logConfigs map[string]bool) (*DefaultFeatureLogger, error) {
	if !enabled {
		return &DefaultFeatureLogger{
			enabled:    false,
			loggers:    make(map[string]*featureFileLogger),
			logDir:     logDir,
			logConfigs: make(map[string]bool),
		}, nil
	}

	// Ensure log directory exists
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create feature logs directory: %w", err)
	}

	fl := &DefaultFeatureLogger{
		enabled:     enabled,
		maxFileSize: maxFileSizeMB * 1024 * 1024,
		loggers:     make(map[string]*featureFileLogger),
		logDir:      logDir,
		logConfigs:  logConfigs,
	}

	// Initialize enabled feature logs
	featureLogNames := []string{"filtering", "certificates", "errors", "performance"}
	for _, name := range featureLogNames {
		if enabled, exists := logConfigs[name]; exists && enabled {
			if err := fl.initializeFeatureLog(name); err != nil {
				fl.Close() // Clean up any initialized loggers
				return nil, fmt.Errorf("failed to initialize %s log: %w", name, err)
			}
		}
	}

	return fl, nil
}

// initializeFeatureLog creates a file logger for a specific feature
func (fl *DefaultFeatureLogger) initializeFeatureLog(name string) error {
	filePath := filepath.Join(fl.logDir, fmt.Sprintf("%s.log", name))
	
	file, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		return fmt.Errorf("failed to open %s log file: %w", name, err)
	}

	logger := &featureFileLogger{
		name:        name,
		filePath:    filePath,
		fileOutput:  file,
		logger:      log.New(file, "", 0), // No prefix, we'll format ourselves
		maxFileSize: fl.maxFileSize,
	}

	fl.loggerMutex.Lock()
	fl.loggers[name] = logger
	fl.loggerMutex.Unlock()

	return nil
}

// getLogger safely retrieves a feature logger
func (fl *DefaultFeatureLogger) getLogger(name string) *featureFileLogger {
	fl.loggerMutex.RLock()
	defer fl.loggerMutex.RUnlock()
	return fl.loggers[name]
}

// writeToFeatureLog writes a formatted message to a specific feature log
func (fl *DefaultFeatureLogger) writeToFeatureLog(logName, message string) {
	if !fl.enabled {
		return
	}

	logger := fl.getLogger(logName)
	if logger == nil {
		return
	}

	logger.mutex.Lock()
	defer logger.mutex.Unlock()

	// Check for rotation before writing
	if err := logger.checkAndRotate(); err != nil {
		fmt.Fprintf(os.Stderr, "Feature log rotation failed for %s: %v\n", logName, err)
	}

	// Format with timestamp
	timestamp := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	formattedMessage := fmt.Sprintf("[%s] %s", timestamp, message)
	
	logger.logger.Println(formattedMessage)
}

// LogFiltering logs filtering decisions to filtering.log
func (fl *DefaultFeatureLogger) LogFiltering(correlationID, target, clientIP, verdict, method, reason string) {
	message := fmt.Sprintf("[%s] target=%s verdict=%s method=%s reason=%s client_ip=%s",
		correlationID, target, verdict, method, reason, clientIP)
	fl.writeToFeatureLog("filtering", message)
}

// LogCertificate logs certificate operations to certificates.log
func (fl *DefaultFeatureLogger) LogCertificate(action, domain string, duration time.Duration, status string, extra map[string]interface{}) {
	message := fmt.Sprintf("action=%s domain=%s status=%s", action, domain, status)
	
	if duration > 0 {
		message += fmt.Sprintf(" duration=%s", duration.String())
	}
	
	// Add extra fields
	for key, value := range extra {
		message += fmt.Sprintf(" %s=%v", key, value)
	}
	
	fl.writeToFeatureLog("certificates", message)
}

// LogError logs errors to errors.log
func (fl *DefaultFeatureLogger) LogError(level, component, error string, extra map[string]interface{}) {
	message := fmt.Sprintf("level=%s component=%s error=%q", level, component, error)
	
	// Add extra fields
	for key, value := range extra {
		message += fmt.Sprintf(" %s=%v", key, value)
	}
	
	fl.writeToFeatureLog("errors", message)
}

// LogPerformance logs performance metrics to performance.log
func (fl *DefaultFeatureLogger) LogPerformance(metric string, value interface{}, extra map[string]interface{}) {
	message := fmt.Sprintf("metric=%s value=%v", metric, value)
	
	// Add extra fields
	for key, val := range extra {
		message += fmt.Sprintf(" %s=%v", key, val)
	}
	
	fl.writeToFeatureLog("performance", message)
}

// Close closes all feature log files
func (fl *DefaultFeatureLogger) Close() error {
	fl.loggerMutex.Lock()
	defer fl.loggerMutex.Unlock()
	
	var lastErr error
	for name, logger := range fl.loggers {
		if err := logger.fileOutput.Close(); err != nil {
			lastErr = fmt.Errorf("failed to close %s log: %w", name, err)
		}
	}
	
	fl.loggers = make(map[string]*featureFileLogger)
	return lastErr
}

// checkAndRotate checks if the log file needs rotation and performs it if necessary
func (ffl *featureFileLogger) checkAndRotate() error {
	// Get current file size
	fileInfo, err := os.Stat(ffl.filePath)
	if err != nil {
		return err
	}

	// Check if rotation is needed
	if fileInfo.Size() < ffl.maxFileSize {
		return nil
	}

	// Close current file
	ffl.fileOutput.Close()

	// Create rotation filename with timestamp
	timestamp := time.Now().Format("2006-01-02_15-04-05")
	dir := filepath.Dir(ffl.filePath)
	base := filepath.Base(ffl.filePath)
	ext := filepath.Ext(base)
	name := base[:len(base)-len(ext)]
	
	rotatedFile := filepath.Join(dir, fmt.Sprintf("%s_%s%s", name, timestamp, ext))

	// Rename current file to rotated filename
	if err := os.Rename(ffl.filePath, rotatedFile); err != nil {
		return fmt.Errorf("failed to rotate log file: %w", err)
	}

	// Create new log file
	file, err := os.OpenFile(ffl.filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		return fmt.Errorf("failed to create new log file after rotation: %w", err)
	}

	// Update logger
	ffl.fileOutput = file
	ffl.logger = log.New(file, "", 0)

	return nil
}