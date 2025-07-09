package storage

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/iamgaru/gander/internal/capture"
)

// StorageManager handles capture storage with compression and rotation
type StorageManager struct {
	config     *StorageConfig
	writers    map[string]*FileWriter
	writersMux sync.RWMutex
	metrics    *StorageMetrics
	enabled    bool
}

// StorageConfig contains storage management configuration
type StorageConfig struct {
	// Basic settings
	Enabled     bool   `json:"enabled"`
	BaseDir     string `json:"base_dir"`
	FilePattern string `json:"file_pattern"`

	// Compression settings
	CompressionEnabled bool            `json:"compression_enabled"`
	CompressionFormat  CompressionType `json:"compression_format"`
	CompressionLevel   int             `json:"compression_level"`

	// Rolling settings
	RollingEnabled  bool            `json:"rolling_enabled"`
	RollingStrategy RollingStrategy `json:"rolling_strategy"`
	MaxFileSize     int64           `json:"max_file_size"` // bytes
	MaxFilesPerDir  int             `json:"max_files_per_dir"`
	RollInterval    time.Duration   `json:"roll_interval"`

	// Retention settings
	RetentionEnabled bool          `json:"retention_enabled"`
	RetentionPeriod  time.Duration `json:"retention_period"`
	MaxStorageSize   int64         `json:"max_storage_size"` // bytes
	CleanupInterval  time.Duration `json:"cleanup_interval"`

	// Capture level settings
	CaptureLevel     CaptureLevel     `json:"capture_level"`
	SelectiveCapture *SelectiveConfig `json:"selective_capture"`

	// Performance settings
	BufferSize        int           `json:"buffer_size"`
	FlushInterval     time.Duration `json:"flush_interval"`
	ConcurrentWriters int           `json:"concurrent_writers"`
}

// CompressionType represents different compression formats
type CompressionType string

const (
	CompressionNone CompressionType = "none"
	CompressionGzip CompressionType = "gzip"
	CompressionZstd CompressionType = "zstd"
	CompressionLZ4  CompressionType = "lz4"
)

// RollingStrategy represents different file rolling strategies
type RollingStrategy string

const (
	RollingBySize RollingStrategy = "size"
	RollingByTime RollingStrategy = "time"
	RollingBoth   RollingStrategy = "both"
)

// CaptureLevel determines what data is captured
type CaptureLevel string

const (
	CaptureLevelMinimal CaptureLevel = "minimal" // Just metadata, no bodies
	CaptureLevelBasic   CaptureLevel = "basic"   // Headers + small bodies
	CaptureLevelFull    CaptureLevel = "full"    // Everything but large bodies
	CaptureLevelDeep    CaptureLevel = "deep"    // Everything including large bodies
	CaptureLevelCustom  CaptureLevel = "custom"  // Use selective config
)

// SelectiveConfig allows fine-grained control over what gets captured
type SelectiveConfig struct {
	CaptureHeaders      bool  `json:"capture_headers"`
	CaptureRequestBody  bool  `json:"capture_request_body"`
	CaptureResponseBody bool  `json:"capture_response_body"`
	MaxBodySize         int64 `json:"max_body_size"`

	// Resource type filtering
	IncludeResourceTypes []string `json:"include_resource_types"`
	ExcludeResourceTypes []string `json:"exclude_resource_types"`

	// Domain filtering
	IncludeDomains []string `json:"include_domains"`
	ExcludeDomains []string `json:"exclude_domains"`

	// Status code filtering
	IncludeStatusCodes []int `json:"include_status_codes"`
	ExcludeStatusCodes []int `json:"exclude_status_codes"`

	// Content type filtering
	IncludeContentTypes []string `json:"include_content_types"`
	ExcludeContentTypes []string `json:"exclude_content_types"`

	// Identity-based filtering
	IncludeIdentities []string `json:"include_identities"`
	ExcludeIdentities []string `json:"exclude_identities"`
}

// StorageMetrics tracks storage system performance
type StorageMetrics struct {
	mutex              sync.RWMutex
	FilesCreated       int64     `json:"files_created"`
	FilesCompressed    int64     `json:"files_compressed"`
	FilesRolled        int64     `json:"files_rolled"`
	FilesDeleted       int64     `json:"files_deleted"`
	BytesWritten       int64     `json:"bytes_written"`
	BytesCompressed    int64     `json:"bytes_compressed"`
	CompressionRatio   float64   `json:"compression_ratio"`
	CurrentStorageSize int64     `json:"current_storage_size"`
	LastCleanup        time.Time `json:"last_cleanup"`
	WriteErrors        int64     `json:"write_errors"`
	AverageWriteTime   float64   `json:"average_write_time_ms"`
}

// FileWriter manages individual file writing with compression and rolling
type FileWriter struct {
	filePath    string
	file        *os.File
	writer      io.Writer
	compressor  io.WriteCloser
	currentSize int64
	createdAt   time.Time
	lastWrite   time.Time
	mutex       sync.Mutex
	config      *StorageConfig
}

// NewStorageManager creates a new storage manager
func NewStorageManager(config *StorageConfig) *StorageManager {
	if config == nil {
		config = DefaultStorageConfig()
	}

	sm := &StorageManager{
		config:  config,
		writers: make(map[string]*FileWriter),
		metrics: &StorageMetrics{},
		enabled: config.Enabled,
	}

	if sm.enabled {
		// Start cleanup routine
		go sm.cleanupRoutine()
	}

	return sm
}

// DefaultStorageConfig returns sensible default configuration
func DefaultStorageConfig() *StorageConfig {
	return &StorageConfig{
		Enabled:     true,
		BaseDir:     "./captures",
		FilePattern: "{domain}/{date}/{resource_type}/capture_{timestamp}.json",

		CompressionEnabled: true,
		CompressionFormat:  CompressionGzip,
		CompressionLevel:   6, // Balanced compression

		RollingEnabled:  true,
		RollingStrategy: RollingBySize,
		MaxFileSize:     50 * 1024 * 1024, // 50MB
		MaxFilesPerDir:  100,
		RollInterval:    time.Hour,

		RetentionEnabled: true,
		RetentionPeriod:  30 * 24 * time.Hour,     // 30 days
		MaxStorageSize:   10 * 1024 * 1024 * 1024, // 10GB
		CleanupInterval:  time.Hour,

		CaptureLevel: CaptureLevelBasic,

		BufferSize:        64 * 1024, // 64KB
		FlushInterval:     5 * time.Second,
		ConcurrentWriters: 10,
	}
}

// StoreCapture stores a capture according to configuration
func (sm *StorageManager) StoreCapture(capture *capture.EnhancedCapture) error {
	if !sm.enabled {
		return nil
	}

	// Apply capture level filtering
	filteredCapture, shouldCapture := sm.applyCaptureLevel(capture)
	if !shouldCapture {
		return nil
	}

	// Generate file path
	filePath := sm.generateFilePath(filteredCapture)

	// Get or create writer for this path
	writer, err := sm.getWriter(filePath)
	if err != nil {
		sm.metrics.WriteErrors++
		return fmt.Errorf("failed to get writer: %w", err)
	}

	// Serialize and write
	startTime := time.Now()
	data, err := json.Marshal(filteredCapture)
	if err != nil {
		sm.metrics.WriteErrors++
		return fmt.Errorf("failed to marshal capture: %w", err)
	}

	err = writer.Write(data)
	if err != nil {
		sm.metrics.WriteErrors++
		return fmt.Errorf("failed to write capture: %w", err)
	}

	// Update metrics
	writeTime := time.Since(startTime).Seconds() * 1000 // ms
	sm.updateMetrics(int64(len(data)), writeTime)

	return nil
}

// applyCaptureLevel filters capture data based on configuration
func (sm *StorageManager) applyCaptureLevel(capture *capture.EnhancedCapture) (*capture.EnhancedCapture, bool) {
	// Create a copy to avoid modifying original
	filtered := *capture

	// Apply selective filtering first if custom level
	if sm.config.CaptureLevel == CaptureLevelCustom && sm.config.SelectiveCapture != nil {
		if !sm.shouldCaptureBySelective(&filtered) {
			return nil, false
		}
		sm.applySelectiveFiltering(&filtered)
		return &filtered, true
	}

	// Apply level-based filtering
	switch sm.config.CaptureLevel {
	case CaptureLevelMinimal:
		// Only metadata, no bodies or headers
		filtered.Request.Body = ""
		filtered.Request.Headers = nil
		filtered.Response.Body = ""
		filtered.Response.Headers = nil

	case CaptureLevelBasic:
		// Headers + small bodies only
		if filtered.Request.BodySize > 4096 { // 4KB
			filtered.Request.Body = fmt.Sprintf("[truncated - %d bytes]", filtered.Request.BodySize)
		}
		if filtered.Response.BodySize > 4096 { // 4KB
			filtered.Response.Body = fmt.Sprintf("[truncated - %d bytes]", filtered.Response.BodySize)
		}

	case CaptureLevelFull:
		// Everything except very large bodies
		if filtered.Request.BodySize > 1024*1024 { // 1MB
			filtered.Request.Body = fmt.Sprintf("[truncated - %d bytes]", filtered.Request.BodySize)
		}
		if filtered.Response.BodySize > 1024*1024 { // 1MB
			filtered.Response.Body = fmt.Sprintf("[truncated - %d bytes]", filtered.Response.BodySize)
		}

	case CaptureLevelDeep:
		// Everything - no filtering
		break
	}

	return &filtered, true
}

// shouldCaptureBySelective determines if capture should be stored based on selective config
func (sm *StorageManager) shouldCaptureBySelective(capture *capture.EnhancedCapture) bool {
	config := sm.config.SelectiveCapture

	// Check resource type filters
	if len(config.IncludeResourceTypes) > 0 {
		found := false
		for _, rt := range config.IncludeResourceTypes {
			if string(capture.ResourceType) == rt {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	if len(config.ExcludeResourceTypes) > 0 {
		for _, rt := range config.ExcludeResourceTypes {
			if string(capture.ResourceType) == rt {
				return false
			}
		}
	}

	// Check domain filters
	if len(config.IncludeDomains) > 0 {
		found := false
		for _, domain := range config.IncludeDomains {
			if capture.Connection.Domain == domain {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	if len(config.ExcludeDomains) > 0 {
		for _, domain := range config.ExcludeDomains {
			if capture.Connection.Domain == domain {
				return false
			}
		}
	}

	// Check status code filters
	if len(config.IncludeStatusCodes) > 0 {
		found := false
		for _, code := range config.IncludeStatusCodes {
			if capture.Response.StatusCode == code {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	if len(config.ExcludeStatusCodes) > 0 {
		for _, code := range config.ExcludeStatusCodes {
			if capture.Response.StatusCode == code {
				return false
			}
		}
	}

	// Check identity filters
	if capture.Identity != nil && capture.Identity.PrimaryIdentity != nil {
		identityID := capture.Identity.PrimaryIdentity.ID

		if len(config.IncludeIdentities) > 0 {
			found := false
			for _, id := range config.IncludeIdentities {
				if identityID == id {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}

		if len(config.ExcludeIdentities) > 0 {
			for _, id := range config.ExcludeIdentities {
				if identityID == id {
					return false
				}
			}
		}
	}

	return true
}

// applySelectiveFiltering applies selective capture settings
func (sm *StorageManager) applySelectiveFiltering(capture *capture.EnhancedCapture) {
	config := sm.config.SelectiveCapture

	if !config.CaptureHeaders {
		capture.Request.Headers = nil
		capture.Response.Headers = nil
	}

	if !config.CaptureRequestBody {
		capture.Request.Body = ""
	} else if config.MaxBodySize > 0 && capture.Request.BodySize > config.MaxBodySize {
		capture.Request.Body = fmt.Sprintf("[truncated - %d bytes]", capture.Request.BodySize)
	}

	if !config.CaptureResponseBody {
		capture.Response.Body = ""
	} else if config.MaxBodySize > 0 && capture.Response.BodySize > config.MaxBodySize {
		capture.Response.Body = fmt.Sprintf("[truncated - %d bytes]", capture.Response.BodySize)
	}
}

// generateFilePath creates the storage path for a capture
func (sm *StorageManager) generateFilePath(enhancedCapture *capture.EnhancedCapture) string {
	// Generate directory structure
	dirStructure := capture.GenerateDirectoryStructure(enhancedCapture, sm.config.BaseDir)

	// Create full directory path
	fullDir := filepath.Join(
		dirStructure.BaseDir,
		dirStructure.DomainDir,
		dirStructure.DateDir,
		dirStructure.ResourceDir,
	)

	// Add compression extension if enabled
	fileName := dirStructure.FileName
	if sm.config.CompressionEnabled {
		switch sm.config.CompressionFormat {
		case CompressionGzip:
			fileName += ".gz"
		case CompressionZstd:
			fileName += ".zst"
		case CompressionLZ4:
			fileName += ".lz4"
		}
	}

	return filepath.Join(fullDir, fileName)
}

// getWriter gets or creates a file writer for the given path
func (sm *StorageManager) getWriter(filePath string) (*FileWriter, error) {
	sm.writersMux.RLock()
	writer, exists := sm.writers[filePath]
	sm.writersMux.RUnlock()

	if exists && !writer.needsRolling() {
		return writer, nil
	}

	sm.writersMux.Lock()
	defer sm.writersMux.Unlock()

	// Double-check after acquiring write lock
	if writer, exists := sm.writers[filePath]; exists && !writer.needsRolling() {
		return writer, nil
	}

	// Create new writer or roll existing one
	if exists && writer.needsRolling() {
		writer.Close()
		delete(sm.writers, filePath)
		sm.metrics.FilesRolled++
	}

	newWriter, err := sm.createWriter(filePath)
	if err != nil {
		return nil, err
	}

	sm.writers[filePath] = newWriter
	sm.metrics.FilesCreated++

	return newWriter, nil
}

// createWriter creates a new file writer with compression
func (sm *StorageManager) createWriter(filePath string) (*FileWriter, error) {
	// Create directory if it doesn't exist
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create directory: %w", err)
	}

	// Create file
	file, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to create file: %w", err)
	}

	writer := &FileWriter{
		filePath:  filePath,
		file:      file,
		createdAt: time.Now(),
		lastWrite: time.Now(),
		config:    sm.config,
	}

	// Set up compression if enabled
	if sm.config.CompressionEnabled {
		switch sm.config.CompressionFormat {
		case CompressionGzip:
			gzWriter, err := gzip.NewWriterLevel(file, sm.config.CompressionLevel)
			if err != nil {
				file.Close()
				return nil, fmt.Errorf("failed to create gzip writer: %w", err)
			}
			writer.compressor = gzWriter
			writer.writer = gzWriter
		default:
			writer.writer = file
		}
	} else {
		writer.writer = file
	}

	return writer, nil
}

// Write writes data to the file
func (fw *FileWriter) Write(data []byte) error {
	fw.mutex.Lock()
	defer fw.mutex.Unlock()

	// Add newline for JSON streaming
	data = append(data, '\n')

	n, err := fw.writer.Write(data)
	if err != nil {
		return err
	}

	fw.currentSize += int64(n)
	fw.lastWrite = time.Now()

	return nil
}

// needsRolling checks if the file needs to be rolled
func (fw *FileWriter) needsRolling() bool {
	fw.mutex.Lock()
	defer fw.mutex.Unlock()

	switch fw.config.RollingStrategy {
	case RollingBySize:
		return fw.currentSize >= fw.config.MaxFileSize
	case RollingByTime:
		return time.Since(fw.createdAt) >= fw.config.RollInterval
	case RollingBoth:
		return fw.currentSize >= fw.config.MaxFileSize ||
			time.Since(fw.createdAt) >= fw.config.RollInterval
	}

	return false
}

// Close closes the file writer
func (fw *FileWriter) Close() error {
	fw.mutex.Lock()
	defer fw.mutex.Unlock()

	if fw.compressor != nil {
		if err := fw.compressor.Close(); err != nil {
			return err
		}
	}

	return fw.file.Close()
}

// updateMetrics updates storage metrics
func (sm *StorageManager) updateMetrics(bytesWritten int64, writeTimeMs float64) {
	sm.metrics.mutex.Lock()
	defer sm.metrics.mutex.Unlock()

	sm.metrics.BytesWritten += bytesWritten

	// Update average write time (simple moving average)
	if sm.metrics.AverageWriteTime == 0 {
		sm.metrics.AverageWriteTime = writeTimeMs
	} else {
		sm.metrics.AverageWriteTime = (sm.metrics.AverageWriteTime + writeTimeMs) / 2
	}
}

// GetMetrics returns current storage metrics
func (sm *StorageManager) GetMetrics() StorageMetrics {
	sm.metrics.mutex.RLock()
	defer sm.metrics.mutex.RUnlock()
	return *sm.metrics
}

// cleanupRoutine runs periodic cleanup of old files
func (sm *StorageManager) cleanupRoutine() {
	ticker := time.NewTicker(sm.config.CleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		if sm.config.RetentionEnabled {
			sm.cleanupOldFiles()
		}
	}
}

// cleanupOldFiles removes old files based on retention policy
func (sm *StorageManager) cleanupOldFiles() {
	cutoff := time.Now().Add(-sm.config.RetentionPeriod)

	err := filepath.Walk(sm.config.BaseDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip errors
		}

		if !info.IsDir() && info.ModTime().Before(cutoff) {
			if err := os.Remove(path); err == nil {
				sm.metrics.mutex.Lock()
				sm.metrics.FilesDeleted++
				sm.metrics.mutex.Unlock()
			}
		}

		return nil
	})

	if err == nil {
		sm.metrics.mutex.Lock()
		sm.metrics.LastCleanup = time.Now()
		sm.metrics.mutex.Unlock()
	}
}

// Shutdown gracefully shuts down the storage manager
func (sm *StorageManager) Shutdown() error {
	sm.writersMux.Lock()
	defer sm.writersMux.Unlock()

	for _, writer := range sm.writers {
		writer.Close()
	}

	return nil
}
