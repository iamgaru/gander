package capture

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/iamgaru/gander/internal/identity"
	"github.com/iamgaru/gander/internal/logging"
)

// EnhancedCaptureManager manages enhanced capture format operations
type EnhancedCaptureManager struct {
	*CaptureManager // Embed existing manager for compatibility
}

// NewEnhancedCaptureManager creates a new enhanced capture manager
func NewEnhancedCaptureManager(captureDir string, enableDebug bool) *EnhancedCaptureManager {
	baseMgr := NewCaptureManager(captureDir, enableDebug)
	return &EnhancedCaptureManager{
		CaptureManager: baseMgr,
	}
}

// CaptureHTTPRequestEnhanced captures an HTTP request using the enhanced format
func (ecm *EnhancedCaptureManager) CaptureHTTPRequestEnhanced(req *http.Request, clientIP string, identityCtx *identity.IdentityContext) (*EnhancedCapture, error) {
	if req == nil {
		return nil, fmt.Errorf("request is nil")
	}

	// Generate unique IDs
	correlationID := ecm.generateCorrelationID(req, clientIP)
	captureID := fmt.Sprintf("%s_%d", correlationID, time.Now().UnixNano())

	// Read and restore body
	var bodyBytes []byte
	var err error
	if req.Body != nil && ecm.config.IncludeBody {
		bodyBytes, err = ecm.readRequestBody(req)
		if err != nil {
			return nil, fmt.Errorf("failed to read request body: %w", err)
		}
	}

	// Limit body size
	if len(bodyBytes) > ecm.config.MaxBodySize {
		bodyBytes = bodyBytes[:ecm.config.MaxBodySize]
	}

	// Extract headers with redaction
	headers := ecm.extractHeaders(req.Header)

	// Parse connection details
	clientParts := strings.Split(clientIP, ":")
	clientIPOnly := clientParts[0]
	clientPort := 0
	if len(clientParts) > 1 {
		if port, err := strconv.Atoi(clientParts[1]); err == nil {
			clientPort = port
		}
	}

	// Determine if this is HTTPS
	protocol := "HTTP"
	tlsVersion := ""
	cipher := ""
	if req.TLS != nil {
		protocol = "HTTPS"
		tlsVersion = getTLSVersionString(req.TLS.Version)
		cipher = getCipherSuiteName(req.TLS.CipherSuite)
	}

	// Create enhanced capture
	enhancedCapture := &EnhancedCapture{
		// Core identifiers
		ID:            captureID,
		CorrelationID: correlationID,
		Timestamp:     time.Now(),

		// Identity information
		Identity: identityCtx,

		// Connection metadata
		Connection: ConnectionMetadata{
			ClientIP:   clientIPOnly,
			ClientPort: clientPort,
			ServerIP:   "", // Will be filled in response
			ServerPort: 0,  // Will be filled in response
			Protocol:   protocol,
			TLSVersion: tlsVersion,
			Cipher:     cipher,
			StartTime:  time.Now(),
			Domain:     req.Host,
			SNI:        req.Host, // Assume SNI matches Host
		},

		// Request data
		Request: RequestData{
			Method:      req.Method,
			URL:         req.URL.String(),
			Path:        req.URL.Path,
			Query:       req.URL.RawQuery,
			HTTPVersion: req.Proto,
			Headers:     headers,
			Body:        string(bodyBytes),
			BodySize:    int64(len(bodyBytes)),
			ContentType: req.Header.Get("Content-Type"),
			UserAgent:   req.Header.Get("User-Agent"),
			Referer:     req.Header.Get("Referer"),
		},

		// Timing information
		StartTime: time.Now(),

		// Capture settings
		CaptureSettings: CaptureSettings{
			CaptureBody:     ecm.config.IncludeBody,
			MaxBodySize:     int64(ecm.config.MaxBodySize),
			CaptureHeaders:  true,
			InspectionLevel: "basic", // Default level
		},
	}

	// Detect resource type
	enhancedCapture.ResourceType = DetectResourceType(&enhancedCapture.Request, nil)

	// Apply automatic tagging
	AutoTagCapture(enhancedCapture)

	// Apply classification
	ClassifyCapture(enhancedCapture)

	// Update stats
	ecm.stats.IncrementRequestsCaptured()
	ecm.stats.AddBytesProcessed(int64(len(bodyBytes)))

	if ecm.enableDebug {
		logging.Request("Captured enhanced HTTP request: %s %s from %s (correlation: %s)",
			req.Method, req.URL.Path, clientIP, correlationID)
	}

	return enhancedCapture, nil
}

// CaptureHTTPResponseEnhanced captures an HTTP response and correlates it with an enhanced request
func (ecm *EnhancedCaptureManager) CaptureHTTPResponseEnhanced(resp *http.Response, clientIP string, requestCapture *EnhancedCapture) error {
	if resp == nil {
		return fmt.Errorf("response is nil")
	}
	if requestCapture == nil {
		return fmt.Errorf("request capture is nil")
	}

	// Read body using configurable strategy
	bodyBytes, err := ecm.readResponseBody(resp)
	if err != nil {
		// Log error but don't fail the entire capture
		logging.Warn("Failed to capture response body (using strategy %s): %v", ecm.config.BodyCaptureStrategy, err)
		bodyBytes = nil // Continue without body
	}

	// Restore body for downstream consumption
	if resp.Body != nil && bodyBytes != nil {
		resp.Body = io.NopCloser(strings.NewReader(string(bodyBytes)))
	}

	// Extract headers with redaction
	headers := ecm.extractHeaders(resp.Header)

	// Complete the enhanced capture
	requestCapture.Response = ResponseData{
		StatusCode:     resp.StatusCode,
		StatusText:     resp.Status,
		Headers:        headers,
		Body:           string(bodyBytes),
		BodySize:       int64(len(bodyBytes)),
		ContentType:    resp.Header.Get("Content-Type"),
		ContentLength:  resp.ContentLength,
		ProcessingTime: time.Since(requestCapture.StartTime),
	}

	// Update timing information
	requestCapture.EndTime = time.Now()
	requestCapture.Duration = requestCapture.EndTime.Sub(requestCapture.StartTime)

	// Re-detect resource type with response data
	requestCapture.ResourceType = DetectResourceType(&requestCapture.Request, &requestCapture.Response)

	// Re-apply automatic tagging with complete data
	AutoTagCapture(requestCapture)

	// Re-apply classification with complete data
	ClassifyCapture(requestCapture)

	// Convert to normalized format for storage
	normalizedCapture := ToNormalizedCapture(requestCapture)

	// Save complete capture in enhanced format
	if err := ecm.saveEnhancedCapture(normalizedCapture); err != nil {
		ecm.stats.IncrementSaveErrors()
		logging.Error("Failed to save enhanced capture: %v", err)
		return err
	} else {
		ecm.stats.IncrementPairsCaptured()
	}

	ecm.stats.IncrementResponsesCaptured()
	ecm.stats.AddBytesProcessed(int64(len(bodyBytes)))

	if ecm.enableDebug {
		logging.Response("Captured enhanced HTTP response: %d %s for %s (duration: %v)",
			resp.StatusCode, resp.Status, requestCapture.CorrelationID, requestCapture.Duration)
	}

	return nil
}

// saveEnhancedCapture saves a normalized capture to disk
func (ecm *EnhancedCaptureManager) saveEnhancedCapture(capture *NormalizedCapture) error {
	// Generate full file path using enhanced directory structure
	fullPath := ecm.generateEnhancedFilePath(capture)

	// Create directory structure if it doesn't exist
	dir := filepath.Dir(fullPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create capture directory: %w", err)
	}

	// Marshal to JSON
	data, err := json.MarshalIndent(capture, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal capture: %w", err)
	}

	// Write file with optional compression
	if ecm.config.EnableGzipFiles {
		if err := ecm.writeCompressedFile(fullPath, data); err != nil {
			return fmt.Errorf("failed to write compressed capture file: %w", err)
		}
	} else {
		if err := os.WriteFile(fullPath, data, 0644); err != nil {
			return fmt.Errorf("failed to write capture file: %w", err)
		}
	}

	if ecm.enableDebug {
		relativePath, _ := filepath.Rel(ecm.captureDir, fullPath)
		logging.Debug("Saved enhanced capture to %s", relativePath)
	}

	return nil
}

// generateEnhancedFilePath creates the file path for normalized captures
func (ecm *EnhancedCaptureManager) generateEnhancedFilePath(capture *NormalizedCapture) string {
	// Use partition date for organization
	year := capture.PartitionDate[:4]
	month := capture.PartitionDate[5:7]
	day := capture.PartitionDate[8:10]

	// Clean domain name for directory usage
	domain := ecm.cleanDomainForPath(capture.Domain)

	// Resource type directory
	resourceType := capture.ResourceType

	// Generate simplified filename for normalized format
	filename := fmt.Sprintf("%s_%s_%s_%d.json",
		capture.PartitionDate,
		capture.RequestMethod,
		resourceType,
		capture.Timestamp.Unix())

	if ecm.config.EnableGzipFiles {
		filename += ".gz"
	}

	// Create hierarchical path: captures/domain/year/month/day/resource_type/filename
	return filepath.Join(
		ecm.captureDir,
		domain,
		year,
		month,
		day,
		resourceType,
		filename,
	)
}

// Helper functions for TLS information
func getTLSVersionString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("TLS 0x%04x", version)
	}
}

func getCipherSuiteName(cipherSuite uint16) string {
	// This is a simplified mapping - in production you'd want a complete mapping
	switch cipherSuite {
	case tls.TLS_RSA_WITH_RC4_128_SHA:
		return "TLS_RSA_WITH_RC4_128_SHA"
	case tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:
		return "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
	case tls.TLS_RSA_WITH_AES_128_CBC_SHA:
		return "TLS_RSA_WITH_AES_128_CBC_SHA"
	case tls.TLS_RSA_WITH_AES_256_CBC_SHA:
		return "TLS_RSA_WITH_AES_256_CBC_SHA"
	case tls.TLS_RSA_WITH_AES_128_CBC_SHA256:
		return "TLS_RSA_WITH_AES_128_CBC_SHA256"
	case tls.TLS_RSA_WITH_AES_128_GCM_SHA256:
		return "TLS_RSA_WITH_AES_128_GCM_SHA256"
	case tls.TLS_RSA_WITH_AES_256_GCM_SHA384:
		return "TLS_RSA_WITH_AES_256_GCM_SHA384"
	case tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:
		return "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA"
	case tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
		return "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"
	case tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:
		return "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"
	case tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA:
		return "TLS_ECDHE_RSA_WITH_RC4_128_SHA"
	case tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:
		return "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"
	case tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:
		return "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"
	case tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
		return "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"
	case tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:
		return "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"
	case tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
		return "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"
	case tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
		return "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
	case tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
		return "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
	case tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
		return "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
	case tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
		return "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
	case tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305:
		return "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305"
	case tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305:
		return "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305"
	default:
		return fmt.Sprintf("CIPHER_0x%04x", cipherSuite)
	}
}

// readRequestBody reads and restores request body
func (ecm *EnhancedCaptureManager) readRequestBody(req *http.Request) ([]byte, error) {
	if req.Body == nil {
		return nil, nil
	}

	// Read all data
	bodyBytes, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}

	// Restore the body for downstream processing
	req.Body = io.NopCloser(strings.NewReader(string(bodyBytes)))

	return bodyBytes, nil
}