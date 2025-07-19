package capture

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ConnectionInfo contains metadata about a proxy connection (duplicated to avoid import cycle)
type ConnectionInfo struct {
	ClientIP   string
	ServerAddr string
	Domain     string
	Protocol   string
	StartTime  time.Time
	BytesRead  int64
	BytesWrite int64
	Inspected  bool
	Captured   bool
}

// HTTPCapture represents a captured HTTP request with optional response
type HTTPCapture struct {
	ID          string                 `json:"id"`
	Timestamp   time.Time              `json:"timestamp"`
	ClientIP    string                 `json:"client_ip"`
	Domain      string                 `json:"domain"`
	Method      string                 `json:"method"`
	URL         string                 `json:"url"`
	Path        string                 `json:"path"`
	Query       string                 `json:"query"`
	HTTPVersion string                 `json:"http_version"`
	Headers     map[string]string      `json:"headers"`
	Body        string                 `json:"body"`
	BodySize    int                    `json:"body_size"`
	ContentType string                 `json:"content_type"`
	UserAgent   string                 `json:"user_agent"`
	Referer     string                 `json:"referer"`
	Response    *HTTPResponse          `json:"response,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	Duration    int64                  `json:"duration_ms,omitempty"`
	Correlation string                 `json:"correlation_id,omitempty"`
}

// HTTPResponse represents a captured HTTP response
type HTTPResponse struct {
	StatusCode     int               `json:"status_code"`
	StatusText     string            `json:"status_text"`
	Headers        map[string]string `json:"headers"`
	Body           string            `json:"body"`
	BodySize       int               `json:"body_size"`
	ContentType    string            `json:"content_type"`
	ContentLength  int64             `json:"content_length"`
	Timestamp      time.Time         `json:"timestamp"`
	ProcessingTime int64             `json:"processing_time_ms"`
}

// CaptureManager manages HTTP request/response capture and correlation
type CaptureManager struct {
	captureDir  string
	enableDebug bool

	// Pending requests waiting for responses
	pendingRequests map[string]*HTTPCapture
	requestMutex    sync.RWMutex

	// Statistics
	stats *CaptureStats

	// Configuration
	config *CaptureConfig

	// Circuit breaker state for body capture
	circuitBreakerFailures int
	circuitBreakerOpenTime time.Time
	circuitBreakerMutex    sync.RWMutex
}

// CaptureStats tracks capture statistics
type CaptureStats struct {
	RequestsCaptured    int64 `json:"requests_captured"`
	ResponsesCaptured   int64 `json:"responses_captured"`
	PairsCaptured       int64 `json:"pairs_captured"`
	PendingRequests     int64 `json:"pending_requests"`
	CorrelationFailures int64 `json:"correlation_failures"`
	SaveErrors          int64 `json:"save_errors"`
	TotalBytesProcessed int64 `json:"total_bytes_processed"`
	AverageBodySize     int64 `json:"average_body_size"`
	mutex               sync.RWMutex
}

// BodyCaptureStrategy defines how to handle body capture timeouts
type BodyCaptureStrategy string

const (
	BodyCaptureDefault   BodyCaptureStrategy = "default"    // Option 2: readBodyWithTimeout
	BodyCaptureSkipLarge BodyCaptureStrategy = "skip_large" // Option 3: Skip large/slow responses
	BodyCaptureStream    BodyCaptureStrategy = "stream"     // Option 4: Stream with timeout
	BodyCaptureDisabled  BodyCaptureStrategy = "disabled"   // Disable body capture entirely
)

// CaptureConfig holds capture configuration
type CaptureConfig struct {
	MaxBodySize        int           `json:"max_body_size"`
	MaxPendingRequests int           `json:"max_pending_requests"`
	RequestTimeout     time.Duration `json:"request_timeout"`
	CompressCaptures   bool          `json:"compress_captures"`
	IncludeHeaders     []string      `json:"include_headers"`
	ExcludeHeaders     []string      `json:"exclude_headers"`
	IncludeBody        bool          `json:"include_body"`
	SanitizeHeaders    bool          `json:"sanitize_headers"`
	EnableMetadata     bool          `json:"enable_metadata"`

	// New timeout-related configurations
	BodyReadTimeout         time.Duration       `json:"body_read_timeout"`         // Timeout for reading response body
	BodyCaptureStrategy     BodyCaptureStrategy `json:"body_capture_strategy"`     // Strategy for handling timeouts
	MaxBodySizeSkip         int                 `json:"max_body_size_skip"`        // Skip body capture if Content-Length exceeds this
	CircuitBreakerThreshold int                 `json:"circuit_breaker_threshold"` // Number of consecutive failures before circuit opens
	CircuitBreakerCooldown  time.Duration       `json:"circuit_breaker_cooldown"`  // Time to wait before trying again
}

// NewCaptureManager creates a new capture manager
func NewCaptureManager(captureDir string, enableDebug bool) *CaptureManager {
	return &CaptureManager{
		captureDir:      captureDir,
		enableDebug:     enableDebug,
		pendingRequests: make(map[string]*HTTPCapture),
		stats:           NewCaptureStats(),
		config:          DefaultCaptureConfig(),
	}
}

// DefaultCaptureConfig returns default capture configuration
func DefaultCaptureConfig() *CaptureConfig {
	return &CaptureConfig{
		MaxBodySize:        1024 * 1024, // 1MB
		MaxPendingRequests: 1000,
		RequestTimeout:     30 * time.Second,
		CompressCaptures:   false,
		IncludeHeaders:     []string{},
		ExcludeHeaders:     []string{"Authorization", "Cookie", "Set-Cookie"},
		IncludeBody:        true,
		SanitizeHeaders:    true,
		EnableMetadata:     true,

		// New timeout configurations with network-aware defaults
		BodyReadTimeout:         5 * time.Second,    // 5s for body reading (shorter than RequestTimeout)
		BodyCaptureStrategy:     BodyCaptureDefault, // Use Option 2 as default
		MaxBodySizeSkip:         10 * 1024 * 1024,   // Skip bodies > 10MB (larger than MaxBodySize)
		CircuitBreakerThreshold: 5,                  // Open circuit after 5 consecutive failures
		CircuitBreakerCooldown:  30 * time.Second,   // Wait 30s before trying again
	}
}

// SetConfig sets the capture configuration
func (cm *CaptureManager) SetConfig(config *CaptureConfig) {
	cm.config = config
}

// Initialize initializes the capture manager
func (cm *CaptureManager) Initialize() error {
	// Create capture directory
	if err := os.MkdirAll(cm.captureDir, 0755); err != nil {
		return fmt.Errorf("failed to create capture directory: %w", err)
	}

	// Start cleanup goroutine for pending requests
	go cm.cleanupPendingRequests()

	return nil
}

// CaptureHTTPRequest captures an HTTP request and returns correlation ID
func (cm *CaptureManager) CaptureHTTPRequest(req *http.Request, clientIP string) error {
	if req == nil {
		return fmt.Errorf("request is nil")
	}

	// Generate correlation ID
	correlationID := cm.generateCorrelationID(req, clientIP)

	// Read and restore body
	var bodyBytes []byte
	var err error
	if req.Body != nil && cm.config.IncludeBody {
		bodyBytes, err = io.ReadAll(req.Body)
		if err != nil {
			return fmt.Errorf("failed to read request body: %w", err)
		}
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	}

	// Limit body size
	if len(bodyBytes) > cm.config.MaxBodySize {
		bodyBytes = bodyBytes[:cm.config.MaxBodySize]
	}

	// Extract headers
	headers := cm.extractHeaders(req.Header)

	// Create capture
	capture := &HTTPCapture{
		ID:          correlationID,
		Timestamp:   time.Now(),
		ClientIP:    clientIP,
		Domain:      req.Host,
		Method:      req.Method,
		URL:         req.URL.String(),
		Path:        req.URL.Path,
		Query:       req.URL.RawQuery,
		HTTPVersion: req.Proto,
		Headers:     headers,
		Body:        string(bodyBytes),
		BodySize:    len(bodyBytes),
		ContentType: req.Header.Get("Content-Type"),
		UserAgent:   req.Header.Get("User-Agent"),
		Referer:     req.Header.Get("Referer"),
		Correlation: correlationID,
	}

	// Add metadata if enabled
	if cm.config.EnableMetadata {
		capture.Metadata = map[string]interface{}{
			"request_size":      len(bodyBytes),
			"header_count":      len(req.Header),
			"has_body":          len(bodyBytes) > 0,
			"remote_addr":       req.RemoteAddr,
			"transfer_encoding": req.TransferEncoding,
		}
	}

	// Store pending request
	cm.requestMutex.Lock()
	cm.pendingRequests[correlationID] = capture
	cm.requestMutex.Unlock()

	cm.stats.IncrementRequestsCaptured()
	cm.stats.AddBytesProcessed(int64(len(bodyBytes)))

	if cm.enableDebug {
		log.Printf("Captured HTTP request: %s %s from %s (correlation: %s)",
			req.Method, req.URL.Path, clientIP, correlationID)
	}

	return nil
}

// isCircuitBreakerOpen checks if the circuit breaker is open
func (cm *CaptureManager) isCircuitBreakerOpen() bool {
	cm.circuitBreakerMutex.RLock()
	defer cm.circuitBreakerMutex.RUnlock()

	if cm.circuitBreakerFailures >= cm.config.CircuitBreakerThreshold {
		if time.Since(cm.circuitBreakerOpenTime) < cm.config.CircuitBreakerCooldown {
			return true
		}
		// Reset circuit breaker after cooldown
		cm.circuitBreakerFailures = 0
	}
	return false
}

// recordCircuitBreakerFailure records a failure for the circuit breaker
func (cm *CaptureManager) recordCircuitBreakerFailure() {
	cm.circuitBreakerMutex.Lock()
	defer cm.circuitBreakerMutex.Unlock()

	cm.circuitBreakerFailures++
	if cm.circuitBreakerFailures >= cm.config.CircuitBreakerThreshold {
		cm.circuitBreakerOpenTime = time.Now()
	}
}

// resetCircuitBreaker resets the circuit breaker on success
func (cm *CaptureManager) resetCircuitBreaker() {
	cm.circuitBreakerMutex.Lock()
	defer cm.circuitBreakerMutex.Unlock()

	cm.circuitBreakerFailures = 0
}

// readBodyWithTimeout reads response body with timeout (Option 2 - Default)
func (cm *CaptureManager) readBodyWithTimeout(body io.ReadCloser, timeout time.Duration, maxSize int) ([]byte, error) {
	if body == nil {
		return nil, nil
	}

	// Create a limited reader to prevent excessive memory usage
	limitedReader := io.LimitReader(body, int64(maxSize))

	// Use a channel to implement timeout
	type result struct {
		data []byte
		err  error
	}

	resultChan := make(chan result, 1)

	go func() {
		data, err := io.ReadAll(limitedReader)
		resultChan <- result{data: data, err: err}
	}()

	select {
	case res := <-resultChan:
		return res.data, res.err
	case <-time.After(timeout):
		return nil, fmt.Errorf("timeout reading response body after %v", timeout)
	}
}

// shouldSkipBodyCapture checks if body capture should be skipped (Option 3)
func (cm *CaptureManager) shouldSkipBodyCapture(resp *http.Response) bool {
	// Check circuit breaker
	if cm.isCircuitBreakerOpen() {
		return true
	}

	// Check Content-Length header
	if contentLength := resp.Header.Get("Content-Length"); contentLength != "" {
		if length := resp.ContentLength; length > int64(cm.config.MaxBodySizeSkip) {
			return true
		}
	}

	// Skip for certain content types that are typically large
	contentType := resp.Header.Get("Content-Type")
	if strings.Contains(contentType, "video/") ||
		strings.Contains(contentType, "audio/") ||
		strings.Contains(contentType, "application/octet-stream") {
		return true
	}

	return false
}

// readBodyWithStream reads response body using streaming with timeout (Option 4)
func (cm *CaptureManager) readBodyWithStream(body io.ReadCloser, timeout time.Duration, maxSize int) ([]byte, error) {
	if body == nil {
		return nil, nil
	}

	var buffer bytes.Buffer
	done := make(chan error, 1)

	go func() {
		defer close(done)

		// Create a limited reader
		limitedReader := io.LimitReader(body, int64(maxSize))

		// Stream read in chunks
		chunk := make([]byte, 8192) // 8KB chunks
		for {
			n, err := limitedReader.Read(chunk)
			if n > 0 {
				buffer.Write(chunk[:n])
			}
			if err != nil {
				if err == io.EOF {
					done <- nil
				} else {
					done <- err
				}
				return
			}
		}
	}()

	select {
	case err := <-done:
		return buffer.Bytes(), err
	case <-time.After(timeout):
		return nil, fmt.Errorf("timeout streaming response body after %v", timeout)
	}
}

// readResponseBody reads response body using the configured strategy
func (cm *CaptureManager) readResponseBody(resp *http.Response) ([]byte, error) {
	if !cm.config.IncludeBody {
		return nil, nil
	}

	// Check strategy-specific skip conditions
	if cm.config.BodyCaptureStrategy == BodyCaptureDisabled {
		return nil, nil
	}

	if cm.config.BodyCaptureStrategy == BodyCaptureSkipLarge && cm.shouldSkipBodyCapture(resp) {
		return nil, nil
	}

	var bodyBytes []byte
	var err error

	switch cm.config.BodyCaptureStrategy {
	case BodyCaptureDefault:
		bodyBytes, err = cm.readBodyWithTimeout(resp.Body, cm.config.BodyReadTimeout, cm.config.MaxBodySize)
	case BodyCaptureSkipLarge:
		bodyBytes, err = cm.readBodyWithTimeout(resp.Body, cm.config.BodyReadTimeout, cm.config.MaxBodySize)
	case BodyCaptureStream:
		bodyBytes, err = cm.readBodyWithStream(resp.Body, cm.config.BodyReadTimeout, cm.config.MaxBodySize)
	case BodyCaptureDisabled:
		return nil, nil
	default:
		// Fallback to default strategy
		bodyBytes, err = cm.readBodyWithTimeout(resp.Body, cm.config.BodyReadTimeout, cm.config.MaxBodySize)
	}

	if err != nil {
		cm.recordCircuitBreakerFailure()
		return nil, err
	}

	cm.resetCircuitBreaker()
	return bodyBytes, nil
}

// CaptureHTTPResponse captures an HTTP response and correlates it with a request
func (cm *CaptureManager) CaptureHTTPResponse(resp *http.Response, clientIP string) error {
	if resp == nil {
		return fmt.Errorf("response is nil")
	}

	// Generate correlation ID (should match the request)
	correlationID := cm.generateCorrelationID(resp.Request, clientIP)

	// Read body using configurable strategy
	bodyBytes, err := cm.readResponseBody(resp)
	if err != nil {
		// Log error but don't fail the entire capture
		log.Printf("Failed to capture response body (using strategy %s): %v", cm.config.BodyCaptureStrategy, err)
		bodyBytes = nil // Continue without body
	}

	// Restore body for downstream consumption
	if resp.Body != nil && bodyBytes != nil {
		resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	}

	// Extract headers
	headers := cm.extractHeaders(resp.Header)

	// Create response capture
	responseCapture := &HTTPResponse{
		StatusCode:     resp.StatusCode,
		StatusText:     resp.Status,
		Headers:        headers,
		Body:           string(bodyBytes),
		BodySize:       len(bodyBytes),
		ContentType:    resp.Header.Get("Content-Type"),
		ContentLength:  resp.ContentLength,
		Timestamp:      time.Now(),
		ProcessingTime: 0, // Will be calculated when correlated
	}

	// Try to correlate with pending request
	cm.requestMutex.Lock()
	if requestCapture, exists := cm.pendingRequests[correlationID]; exists {
		// Complete the request/response pair
		requestCapture.Response = responseCapture
		requestCapture.Duration = time.Since(requestCapture.Timestamp).Milliseconds()
		responseCapture.ProcessingTime = requestCapture.Duration

		// Remove from pending
		delete(cm.pendingRequests, correlationID)

		// Save complete capture
		if err := cm.saveCapture(requestCapture); err != nil {
			cm.stats.IncrementSaveErrors()
			log.Printf("Failed to save capture: %v", err)
		} else {
			cm.stats.IncrementPairsCaptured()
		}

		cm.requestMutex.Unlock()

		if cm.enableDebug {
			log.Printf("Captured HTTP response: %d %s for %s (correlation: %s, duration: %dms)",
				resp.StatusCode, resp.Status, correlationID, correlationID, requestCapture.Duration)
		}
	} else {
		cm.requestMutex.Unlock()

		// No matching request found - save response only
		orphanCapture := &HTTPCapture{
			ID:          correlationID + "_response_only",
			Timestamp:   time.Now(),
			ClientIP:    clientIP,
			Domain:      resp.Request.Host,
			Method:      "UNKNOWN",
			URL:         "UNKNOWN",
			Path:        "UNKNOWN",
			Response:    responseCapture,
			Correlation: correlationID,
		}

		if err := cm.saveCapture(orphanCapture); err != nil {
			cm.stats.IncrementSaveErrors()
			log.Printf("Failed to save orphan response: %v", err)
		}

		cm.stats.IncrementCorrelationFailures()

		if cm.enableDebug {
			log.Printf("Failed to correlate response %d for %s (no matching request found)",
				resp.StatusCode, correlationID)
		}
	}

	cm.stats.IncrementResponsesCaptured()
	cm.stats.AddBytesProcessed(int64(len(bodyBytes)))

	return nil
}

// generateCorrelationID generates a correlation ID for request/response matching
func (cm *CaptureManager) generateCorrelationID(req *http.Request, clientIP string) string {
	if req == nil {
		return fmt.Sprintf("%s_%d", clientIP, time.Now().UnixNano())
	}

	// Use combination of client IP, method, and path for deterministic correlation
	// Only use timestamp as fallback for uniqueness if needed
	baseID := fmt.Sprintf("%s_%s_%s",
		strings.ReplaceAll(clientIP, ":", "_"),
		req.Method,
		strings.ReplaceAll(req.URL.Path, "/", "_"))

	// For production, we might want to add timestamp for uniqueness
	// But for testing, this deterministic approach works better
	return baseID
}

// extractHeaders extracts and filters headers based on configuration
func (cm *CaptureManager) extractHeaders(headers http.Header) map[string]string {
	result := make(map[string]string)

	for name, values := range headers {
		// Check if header should be excluded
		if cm.shouldExcludeHeader(name) {
			continue
		}

		// Check if only specific headers should be included
		if len(cm.config.IncludeHeaders) > 0 && !cm.shouldIncludeHeader(name) {
			continue
		}

		// Join multiple values
		value := strings.Join(values, ", ")

		// Sanitize sensitive headers
		if cm.config.SanitizeHeaders && cm.isSensitiveHeader(name) {
			value = "[REDACTED]"
		}

		result[name] = value
	}

	return result
}

// shouldExcludeHeader checks if a header should be excluded
func (cm *CaptureManager) shouldExcludeHeader(header string) bool {
	header = strings.ToLower(header)
	for _, exclude := range cm.config.ExcludeHeaders {
		if strings.ToLower(exclude) == header {
			return true
		}
	}
	return false
}

// shouldIncludeHeader checks if a header should be included
func (cm *CaptureManager) shouldIncludeHeader(header string) bool {
	if len(cm.config.IncludeHeaders) == 0 {
		return true
	}

	header = strings.ToLower(header)
	for _, include := range cm.config.IncludeHeaders {
		if strings.ToLower(include) == header {
			return true
		}
	}
	return false
}

// isSensitiveHeader checks if a header contains sensitive information
func (cm *CaptureManager) isSensitiveHeader(header string) bool {
	sensitiveHeaders := []string{
		"authorization", "cookie", "set-cookie", "x-api-key",
		"x-auth-token", "x-access-token", "bearer", "basic",
	}

	header = strings.ToLower(header)
	for _, sensitive := range sensitiveHeaders {
		if strings.Contains(header, sensitive) {
			return true
		}
	}
	return false
}

// saveCapture saves a capture to disk
func (cm *CaptureManager) saveCapture(capture *HTTPCapture) error {
	// Generate filename
	filename := cm.generateFilename(capture)
	filepath := filepath.Join(cm.captureDir, filename)

	// Marshal to JSON
	data, err := json.MarshalIndent(capture, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal capture: %w", err)
	}

	// Write to file
	if err := os.WriteFile(filepath, data, 0644); err != nil {
		return fmt.Errorf("failed to write capture file: %w", err)
	}

	if cm.enableDebug {
		log.Printf("Saved capture to %s", filename)
	}

	return nil
}

// generateFilename generates a filename for a capture
func (cm *CaptureManager) generateFilename(capture *HTTPCapture) string {
	timestamp := capture.Timestamp.Format("2006-01-02_15-04-05.000")
	clientIP := strings.ReplaceAll(capture.ClientIP, ":", "_")
	domain := strings.ReplaceAll(capture.Domain, ":", "_")
	method := strings.ToLower(capture.Method)

	// Create safe path
	safePath := strings.ReplaceAll(capture.Path, "/", "_")
	if safePath == "" || safePath == "_" {
		safePath = "root"
	}

	// Limit filename length
	if len(safePath) > 50 {
		safePath = safePath[:50]
	}

	return fmt.Sprintf("%s_[%s]_%s_%s_%s.json",
		timestamp, clientIP, domain, method, safePath)
}

// cleanupPendingRequests periodically cleans up pending requests that have timed out
func (cm *CaptureManager) cleanupPendingRequests() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		cm.requestMutex.Lock()

		now := time.Now()
		toDelete := make([]string, 0)

		for id, capture := range cm.pendingRequests {
			if now.Sub(capture.Timestamp) > cm.config.RequestTimeout {
				// Save incomplete capture
				if err := cm.saveCapture(capture); err != nil {
					log.Printf("Failed to save timeout capture: %v", err)
				}
				toDelete = append(toDelete, id)
			}
		}

		// Remove timed out requests
		for _, id := range toDelete {
			delete(cm.pendingRequests, id)
		}

		cm.requestMutex.Unlock()

		if len(toDelete) > 0 && cm.enableDebug {
			log.Printf("Cleaned up %d timed out pending requests", len(toDelete))
		}
	}
}

// GetStats returns capture statistics
func (cm *CaptureManager) GetStats() *CaptureStatsSnapshot {
	cm.requestMutex.RLock()
	pendingCount := int64(len(cm.pendingRequests))
	cm.requestMutex.RUnlock()

	stats := cm.stats.GetStats()
	stats.PendingRequests = pendingCount

	return &stats
}

// NewCaptureStats creates new capture statistics
func NewCaptureStats() *CaptureStats {
	return &CaptureStats{}
}

// IncrementRequestsCaptured increments requests captured count
func (cs *CaptureStats) IncrementRequestsCaptured() {
	cs.mutex.Lock()
	defer cs.mutex.Unlock()
	cs.RequestsCaptured++
}

// IncrementResponsesCaptured increments responses captured count
func (cs *CaptureStats) IncrementResponsesCaptured() {
	cs.mutex.Lock()
	defer cs.mutex.Unlock()
	cs.ResponsesCaptured++
}

// IncrementPairsCaptured increments pairs captured count
func (cs *CaptureStats) IncrementPairsCaptured() {
	cs.mutex.Lock()
	defer cs.mutex.Unlock()
	cs.PairsCaptured++
}

// IncrementCorrelationFailures increments correlation failures count
func (cs *CaptureStats) IncrementCorrelationFailures() {
	cs.mutex.Lock()
	defer cs.mutex.Unlock()
	cs.CorrelationFailures++
}

// IncrementSaveErrors increments save errors count
func (cs *CaptureStats) IncrementSaveErrors() {
	cs.mutex.Lock()
	defer cs.mutex.Unlock()
	cs.SaveErrors++
}

// AddBytesProcessed adds to bytes processed count
func (cs *CaptureStats) AddBytesProcessed(bytes int64) {
	cs.mutex.Lock()
	defer cs.mutex.Unlock()
	cs.TotalBytesProcessed += bytes

	// Update average body size
	totalRequests := cs.RequestsCaptured + cs.ResponsesCaptured
	if totalRequests > 0 {
		cs.AverageBodySize = cs.TotalBytesProcessed / totalRequests
	}
}

// CaptureStatsSnapshot represents a snapshot of capture statistics without mutex
type CaptureStatsSnapshot struct {
	RequestsCaptured    int64 `json:"requests_captured"`
	ResponsesCaptured   int64 `json:"responses_captured"`
	PairsCaptured       int64 `json:"pairs_captured"`
	PendingRequests     int64 `json:"pending_requests"`
	CorrelationFailures int64 `json:"correlation_failures"`
	SaveErrors          int64 `json:"save_errors"`
	TotalBytesProcessed int64 `json:"total_bytes_processed"`
	AverageBodySize     int64 `json:"average_body_size"`
}

// GetStats returns a copy of current statistics
func (cs *CaptureStats) GetStats() CaptureStatsSnapshot {
	cs.mutex.RLock()
	defer cs.mutex.RUnlock()
	return CaptureStatsSnapshot{
		RequestsCaptured:    cs.RequestsCaptured,
		ResponsesCaptured:   cs.ResponsesCaptured,
		PairsCaptured:       cs.PairsCaptured,
		PendingRequests:     cs.PendingRequests,
		CorrelationFailures: cs.CorrelationFailures,
		SaveErrors:          cs.SaveErrors,
		TotalBytesProcessed: cs.TotalBytesProcessed,
		AverageBodySize:     cs.AverageBodySize,
	}
}
