package inspection

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/iamgaru/gander/internal/config"
)

// SmartCaptureWrapper wraps the existing capture handler with smart inspection logic
type SmartCaptureWrapper struct {
	inspector      *ContentInspector
	originalHandler CaptureHandler
}

// CaptureHandler interface matches the one in relay package
type CaptureHandler interface {
	CaptureHTTPRequest(req *http.Request, clientIP string) error
	CaptureHTTPResponse(resp *http.Response, clientIP string) error
}

// NewSmartCaptureWrapper creates a wrapper that adds intelligent inspection to capture
func NewSmartCaptureWrapper(cfg *config.InspectionConfig, originalHandler CaptureHandler) *SmartCaptureWrapper {
	return &SmartCaptureWrapper{
		inspector:       NewContentInspector(cfg),
		originalHandler: originalHandler,
	}
}

// CaptureHTTPRequest captures HTTP requests with smart inspection
func (w *SmartCaptureWrapper) CaptureHTTPRequest(req *http.Request, clientIP string) error {
	if !w.shouldCaptureRequest(req) {
		return nil // Skip capture based on inspection rules
	}
	
	return w.originalHandler.CaptureHTTPRequest(req, clientIP)
}

// CaptureHTTPResponse captures HTTP responses with smart inspection
func (w *SmartCaptureWrapper) CaptureHTTPResponse(resp *http.Response, clientIP string) error {
	if !w.shouldCaptureResponse(resp) {
		return nil // Skip capture based on inspection rules
	}
	
	return w.originalHandler.CaptureHTTPResponse(resp, clientIP)
}

// shouldCaptureRequest determines if a request should be captured
func (w *SmartCaptureWrapper) shouldCaptureRequest(req *http.Request) bool {
	ctx := w.createInspectionContext(req.URL, req.Header, req.ContentLength)
	result := w.inspector.InspectContent(ctx)
	
	return result.Decision == DecisionInspect || result.Decision == DecisionConditional
}

// shouldCaptureResponse determines if a response should be captured
func (w *SmartCaptureWrapper) shouldCaptureResponse(resp *http.Response) bool {
	var reqURL *url.URL
	if resp.Request != nil {
		reqURL = resp.Request.URL
	}
	
	ctx := w.createInspectionContext(reqURL, resp.Header, resp.ContentLength)
	result := w.inspector.InspectContent(ctx)
	
	return result.Decision == DecisionInspect || result.Decision == DecisionConditional
}

// createInspectionContext creates an inspection context from HTTP data
func (w *SmartCaptureWrapper) createInspectionContext(reqURL *url.URL, headers http.Header, contentLength int64) *InspectionContext {
	ctx := &InspectionContext{
		Headers:     headers,
		ContentSize: contentLength,
		IsStreaming: contentLength < 0,
	}
	
	if reqURL != nil {
		ctx.URL = reqURL.String()
		ctx.Domain = reqURL.Host
	}
	
	// Get content type from headers
	if contentType := headers.Get("Content-Type"); contentType != "" {
		ctx.ContentType = contentType
	}
	
	return ctx
}

// InspectionMiddleware provides middleware for HTTP handlers that need inspection
type InspectionMiddleware struct {
	inspector *ContentInspector
}

// NewInspectionMiddleware creates a new inspection middleware
func NewInspectionMiddleware(cfg *config.InspectionConfig) *InspectionMiddleware {
	return &InspectionMiddleware{
		inspector: NewContentInspector(cfg),
	}
}

// ShouldInspectRequest checks if an HTTP request should be inspected
func (m *InspectionMiddleware) ShouldInspectRequest(req *http.Request) *InspectionResult {
	ctx := &InspectionContext{
		URL:         req.URL.String(),
		Domain:      req.URL.Host,
		ContentType: req.Header.Get("Content-Type"),
		ContentSize: req.ContentLength,
		Headers:     req.Header,
		IsStreaming: req.ContentLength < 0,
	}
	
	return m.inspector.InspectContent(ctx)
}

// ShouldInspectResponse checks if an HTTP response should be inspected
func (m *InspectionMiddleware) ShouldInspectResponse(resp *http.Response) *InspectionResult {
	var reqURL *url.URL
	if resp.Request != nil {
		reqURL = resp.Request.URL
	}
	
	ctx := &InspectionContext{
		ContentType: resp.Header.Get("Content-Type"),
		ContentSize: resp.ContentLength,
		Headers:     resp.Header,
		IsStreaming: resp.ContentLength < 0,
	}
	
	if reqURL != nil {
		ctx.URL = reqURL.String()
		ctx.Domain = reqURL.Host
	}
	
	return m.inspector.InspectContent(ctx)
}

// ExtractDomainFromHost extracts domain from host header, handling ports
func ExtractDomainFromHost(host string) string {
	// Remove port if present
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		return host[:idx]
	}
	return host
}

// IsStaticContent checks if content type represents static content
func IsStaticContent(contentType string) bool {
	staticTypes := []string{
		"image/",
		"video/",
		"audio/",
		"font/",
		"application/octet-stream",
		"application/zip",
		"application/pdf",
	}
	
	for _, staticType := range staticTypes {
		if strings.HasPrefix(contentType, staticType) {
			return true
		}
	}
	
	return false
}

// GetContentCategory categorizes content type into inspection categories
func GetContentCategory(contentType string) string {
	// Remove parameters from content type
	if idx := strings.Index(contentType, ";"); idx != -1 {
		contentType = contentType[:idx]
	}
	contentType = strings.TrimSpace(contentType)
	
	switch {
	case strings.HasPrefix(contentType, "text/"):
		return "text"
	case strings.HasPrefix(contentType, "application/javascript") || strings.HasPrefix(contentType, "text/javascript"):
		return "script"
	case strings.HasPrefix(contentType, "application/json"):
		return "data"
	case strings.HasPrefix(contentType, "image/"):
		return "image"
	case strings.HasPrefix(contentType, "video/"):
		return "video"
	case strings.HasPrefix(contentType, "audio/"):
		return "audio"
	case strings.HasPrefix(contentType, "font/"):
		return "font"
	default:
		return "other"
	}
}

// GetInspectionPriority returns priority level for content inspection
func GetInspectionPriority(contentType string) int {
	category := GetContentCategory(contentType)
	
	switch category {
	case "text", "script", "data":
		return 1 // High priority
	case "image":
		return 2 // Medium priority
	case "video", "audio":
		return 3 // Low priority (conditional)
	default:
		return 4 // Very low priority (usually skip)
	}
}

// FormatInspectionResult formats an inspection result for logging
func FormatInspectionResult(result *InspectionResult, ctx *InspectionContext) string {
	return fmt.Sprintf(
		"Inspection decision: %s | Reason: %s | URL: %s | Content-Type: %s | Size: %d bytes",
		result.Decision.String(),
		result.Reason,
		ctx.URL,
		ctx.ContentType,
		ctx.ContentSize,
	)
}

// CreateSampleConfig creates a sample inspection configuration for testing
func CreateSampleConfig() *config.InspectionConfig {
	return &config.InspectionConfig{
		GlobalRules: config.InspectionRules{
			AlwaysInspect: []string{
				"text/html",
				"text/plain",
				"application/json",
				"application/xml",
				"text/xml",
				"application/javascript",
				"text/javascript",
				"text/css",
			},
			ConditionalInspect: []string{
				"image/jpeg",
				"image/png",
				"image/gif",
				"image/webp",
				"image/svg+xml",
			},
			NeverInspect: []string{
				"application/octet-stream",
				"application/zip",
				"application/x-rar-compressed",
				"video/mp4",
				"video/webm",
				"audio/mp3",
				"audio/wav",
				"font/woff",
				"font/woff2",
			},
			SizeLimits: config.SizeLimitsConfig{
				MaxInspectSize:        "10MB",
				ImageMaxSize:          "5MB",
				StreamingBufferSize:   "1MB",
				StreamingInspectBytes: "4KB",
			},
			URLPatterns: config.URLPatternsConfig{
				ForceInspect: []string{},
				ForceSkip:    []string{},
			},
		},
		DomainOverrides: map[string]config.InspectionRules{
			"*.youtube.com": {
				AlwaysInspect: []string{"text/html"},
				NeverInspect:  []string{"video/mp4", "video/webm"},
				SizeLimits: config.SizeLimitsConfig{
					MaxInspectSize:        "1MB",
					StreamingInspectBytes: "2KB",
				},
				URLPatterns: config.URLPatternsConfig{
					ForceInspect: []string{},
					ForceSkip:    []string{},
				},
			},
		},
		AIPreparation: config.AIPreparationConfig{
			Enabled:            true,
			MetadataCapture:    true,
			ContentPreviewSize: "1KB",
			QueueDirectory:     "ai_queue",
			SupportedAnalysis:  []string{"image_ocr", "video_transcript"},
			MaxQueueSize:       1000,
			CleanupAfterDays:   7,
		},
	}
}