package capture

import (
	"fmt"
	"mime"
	"path/filepath"
	"strings"
	"time"

	"github.com/iamgaru/gander/internal/identity"
)

// ResourceType represents the type of HTTP resource
type ResourceType string

const (
	ResourceAPI      ResourceType = "api"
	ResourceWebPage  ResourceType = "webpage"
	ResourceImage    ResourceType = "image"
	ResourceCSS      ResourceType = "css"
	ResourceJS       ResourceType = "javascript"
	ResourceFont     ResourceType = "font"
	ResourceVideo    ResourceType = "video"
	ResourceAudio    ResourceType = "audio"
	ResourceDocument ResourceType = "document"
	ResourceArchive  ResourceType = "archive"
	ResourceOther    ResourceType = "other"
)

// ConnectionMetadata contains connection-level information
type ConnectionMetadata struct {
	ClientIP   string    `json:"client_ip"`
	ClientPort int       `json:"client_port"`
	ServerIP   string    `json:"server_ip"`
	ServerPort int       `json:"server_port"`
	Protocol   string    `json:"protocol"`
	TLSVersion string    `json:"tls_version,omitempty"`
	Cipher     string    `json:"cipher,omitempty"`
	StartTime  time.Time `json:"start_time"`
	Domain     string    `json:"domain"`
	SNI        string    `json:"sni,omitempty"`
}

// RequestData contains HTTP request information
type RequestData struct {
	Method      string            `json:"method"`
	URL         string            `json:"url"`
	Path        string            `json:"path"`
	Query       string            `json:"query,omitempty"`
	HTTPVersion string            `json:"http_version"`
	Headers     map[string]string `json:"headers"`
	Body        string            `json:"body,omitempty"`
	BodySize    int64             `json:"body_size"`
	ContentType string            `json:"content_type,omitempty"`
	UserAgent   string            `json:"user_agent,omitempty"`
	Referer     string            `json:"referer,omitempty"`
}

// ResponseData contains HTTP response information
type ResponseData struct {
	StatusCode     int               `json:"status_code"`
	StatusText     string            `json:"status_text"`
	Headers        map[string]string `json:"headers"`
	Body           string            `json:"body,omitempty"`
	BodySize       int64             `json:"body_size"`
	ContentType    string            `json:"content_type,omitempty"`
	ContentLength  int64             `json:"content_length"`
	ProcessingTime time.Duration     `json:"processing_time_ms"`
}

// EnhancedCapture represents the improved capture format with identity and better organization
type EnhancedCapture struct {
	// Core identifiers
	ID            string    `json:"id"`
	CorrelationID string    `json:"correlation_id"`
	SessionID     string    `json:"session_id,omitempty"`
	Timestamp     time.Time `json:"timestamp"`

	// Identity information
	Identity *identity.IdentityContext `json:"identity,omitempty"`

	// Connection metadata
	Connection ConnectionMetadata `json:"connection"`

	// Request and response data
	Request  RequestData  `json:"request"`
	Response ResponseData `json:"response"`

	// Classification and metadata
	ResourceType ResourceType           `json:"resource_type"`
	Category     string                 `json:"category"`
	Tags         []string               `json:"tags,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`

	// Timing information
	Duration  time.Duration `json:"duration_ms"`
	StartTime time.Time     `json:"start_time"`
	EndTime   time.Time     `json:"end_time"`

	// Capture settings
	CaptureSettings CaptureSettings `json:"capture_settings"`
}

// CaptureSettings contains configuration for how this capture was recorded
type CaptureSettings struct {
	CaptureBody     bool   `json:"capture_body"`
	MaxBodySize     int64  `json:"max_body_size"`
	CaptureHeaders  bool   `json:"capture_headers"`
	InspectionLevel string `json:"inspection_level"` // "basic", "full", "deep"
	FilterApplied   string `json:"filter_applied,omitempty"`
}

// CaptureDirectoryStructure defines how captures are organized
type CaptureDirectoryStructure struct {
	BaseDir     string `json:"base_dir"`
	DomainDir   string `json:"domain_dir"`
	DateDir     string `json:"date_dir"`
	ResourceDir string `json:"resource_dir"`
	FileName    string `json:"file_name"`
}

// DetectResourceType determines the resource type from request/response data
func DetectResourceType(req *RequestData, resp *ResponseData) ResourceType {
	// Check URL path first
	if resourceType := detectFromPath(req.Path); resourceType != ResourceOther {
		return resourceType
	}

	// Check Content-Type header
	if resourceType := detectFromContentType(resp.ContentType); resourceType != ResourceOther {
		return resourceType
	}

	// Check request patterns
	if resourceType := detectFromRequestPattern(req); resourceType != ResourceOther {
		return resourceType
	}

	return ResourceOther
}

// detectFromPath determines resource type from URL path
func detectFromPath(path string) ResourceType {
	if path == "" {
		return ResourceOther
	}

	// Extract file extension
	ext := strings.ToLower(filepath.Ext(path))

	switch ext {
	case ".js":
		return ResourceJS
	case ".css":
		return ResourceCSS
	case ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".svg":
		return ResourceImage
	case ".woff", ".woff2", ".ttf", ".otf", ".eot":
		return ResourceFont
	case ".mp4", ".webm", ".avi", ".mov", ".wmv":
		return ResourceVideo
	case ".mp3", ".wav", ".flac", ".aac", ".ogg":
		return ResourceAudio
	case ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx":
		return ResourceDocument
	case ".zip", ".tar", ".gz", ".rar", ".7z":
		return ResourceArchive
	case ".html", ".htm":
		return ResourceWebPage
	case ".json", ".xml":
		return ResourceAPI
	}

	// Check path patterns
	pathLower := strings.ToLower(path)
	if strings.Contains(pathLower, "/api/") ||
		strings.Contains(pathLower, "/v1/") ||
		strings.Contains(pathLower, "/v2/") ||
		strings.Contains(pathLower, "/graphql") ||
		strings.Contains(pathLower, "/rest/") {
		return ResourceAPI
	}

	return ResourceOther
}

// detectFromContentType determines resource type from Content-Type header
func detectFromContentType(contentType string) ResourceType {
	if contentType == "" {
		return ResourceOther
	}

	// Parse media type
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return ResourceOther
	}

	switch {
	case strings.HasPrefix(mediaType, "image/"):
		return ResourceImage
	case strings.HasPrefix(mediaType, "video/"):
		return ResourceVideo
	case strings.HasPrefix(mediaType, "audio/"):
		return ResourceAudio
	case mediaType == "text/css":
		return ResourceCSS
	case mediaType == "application/javascript" || mediaType == "text/javascript":
		return ResourceJS
	case mediaType == "text/html":
		return ResourceWebPage
	case mediaType == "application/json" || mediaType == "application/xml" || mediaType == "text/xml":
		return ResourceAPI
	case mediaType == "application/pdf":
		return ResourceDocument
	case strings.Contains(mediaType, "font"):
		return ResourceFont
	case strings.Contains(mediaType, "zip") || strings.Contains(mediaType, "archive"):
		return ResourceArchive
	}

	return ResourceOther
}

// detectFromRequestPattern determines resource type from request patterns
func detectFromRequestPattern(req *RequestData) ResourceType {
	// Check for AJAX/API patterns
	if req.Headers != nil {
		if xRequestedWith := req.Headers["X-Requested-With"]; xRequestedWith == "XMLHttpRequest" {
			return ResourceAPI
		}

		if accept := req.Headers["Accept"]; strings.Contains(accept, "application/json") {
			return ResourceAPI
		}
	}

	// Check HTTP method
	if req.Method == "POST" || req.Method == "PUT" || req.Method == "PATCH" || req.Method == "DELETE" {
		// Non-GET methods are often API calls
		return ResourceAPI
	}

	return ResourceOther
}

// GenerateDirectoryStructure creates the directory structure for a capture
func GenerateDirectoryStructure(capture *EnhancedCapture, baseDir string) CaptureDirectoryStructure {
	// Clean domain name for directory
	domain := strings.ReplaceAll(capture.Connection.Domain, ":", "_")
	domain = strings.ReplaceAll(domain, "*", "_")

	// Date directory
	dateDir := capture.Timestamp.Format("2006-01-02")

	// Resource type directory
	resourceDir := string(capture.ResourceType)

	// Generate filename
	fileName := generateFileName(capture)

	return CaptureDirectoryStructure{
		BaseDir:     baseDir,
		DomainDir:   domain,
		DateDir:     dateDir,
		ResourceDir: resourceDir,
		FileName:    fileName,
	}
}

// generateFileName creates a filename for the capture
func generateFileName(capture *EnhancedCapture) string {
	// Base filename with timestamp and method
	base := capture.Timestamp.Format("15-04-05.000")

	// Add client info if available
	clientInfo := strings.ReplaceAll(capture.Connection.ClientIP, ":", "_")
	if capture.Connection.ClientPort > 0 {
		clientInfo += fmt.Sprintf("_%d", capture.Connection.ClientPort)
	}

	// Add method and path info
	method := strings.ToLower(capture.Request.Method)
	path := strings.ReplaceAll(capture.Request.Path, "/", "_")
	path = strings.ReplaceAll(path, "?", "_")
	path = strings.ReplaceAll(path, "&", "_")

	// Truncate path if too long
	if len(path) > 50 {
		path = path[:50]
	}

	return fmt.Sprintf("%s_[%s]_%s_%s%s.json",
		base, clientInfo, capture.Connection.Domain, method, path)
}

// NormalizedCapture represents a flattened, database-ready capture format
type NormalizedCapture struct {
	// Core identifiers - flattened for easy indexing
	ID            string    `json:"id"`
	CorrelationID string    `json:"correlation_id"`
	SessionID     string    `json:"session_id,omitempty"`
	Timestamp     time.Time `json:"timestamp"`

	// Connection data - flattened
	ClientIP     string    `json:"client_ip"`
	ClientPort   int       `json:"client_port"`
	ServerIP     string    `json:"server_ip"`
	ServerPort   int       `json:"server_port"`
	Protocol     string    `json:"protocol"`
	TLSVersion   string    `json:"tls_version,omitempty"`
	Cipher       string    `json:"cipher,omitempty"`
	Domain       string    `json:"domain"`
	SNI          string    `json:"sni,omitempty"`

	// Request data - flattened and normalized
	RequestMethod      string    `json:"request_method"`
	RequestURL         string    `json:"request_url"`
	RequestPath        string    `json:"request_path"`
	RequestQuery       string    `json:"request_query,omitempty"`
	RequestHTTPVersion string    `json:"request_http_version"`
	RequestContentType string    `json:"request_content_type,omitempty"`
	RequestUserAgent   string    `json:"request_user_agent,omitempty"`
	RequestReferer     string    `json:"request_referer,omitempty"`
	RequestBodySize    int64     `json:"request_body_size"`
	RequestBodyHash    string    `json:"request_body_hash,omitempty"`
	RequestBodyPreview string    `json:"request_body_preview,omitempty"` // First 1KB for preview

	// Response data - flattened and normalized  
	ResponseStatusCode     int       `json:"response_status_code"`
	ResponseStatusText     string    `json:"response_status_text"`
	ResponseContentType    string    `json:"response_content_type,omitempty"`
	ResponseContentLength  int64     `json:"response_content_length"`
	ResponseBodySize       int64     `json:"response_body_size"`
	ResponseBodyHash       string    `json:"response_body_hash,omitempty"`
	ResponseBodyPreview    string    `json:"response_body_preview,omitempty"` // First 1KB for preview
	ResponseTimestamp      time.Time `json:"response_timestamp"`

	// Timing data - flattened
	DurationMs      int64     `json:"duration_ms"`
	ProcessingTimeMs int64    `json:"processing_time_ms"`
	StartTime       time.Time `json:"start_time"`
	EndTime         time.Time `json:"end_time"`

	// Classification - flattened for easy filtering
	ResourceType     string   `json:"resource_type"`
	Category         string   `json:"category"`
	Tags             []string `json:"tags,omitempty"`
	IsEncrypted      bool     `json:"is_encrypted"`
	IsSuccessful     bool     `json:"is_successful"` // 2xx status
	IsClientError    bool     `json:"is_client_error"` // 4xx status
	IsServerError    bool     `json:"is_server_error"` // 5xx status
	IsSlowRequest    bool     `json:"is_slow_request"`
	IsLargeResponse  bool     `json:"is_large_response"`

	// Identity data - flattened
	IdentityID         string  `json:"identity_id,omitempty"`
	IdentityType       string  `json:"identity_type,omitempty"`
	IdentityConfidence float64 `json:"identity_confidence,omitempty"`
	IsIdentified       bool    `json:"is_identified"`
	IsPrivateNetwork   bool    `json:"is_private_network"`
	IsTrusted          bool    `json:"is_trusted"`

	// Headers - normalized and redacted
	ImportantHeaders map[string]string `json:"important_headers,omitempty"`
	HeaderCount      int               `json:"header_count"`

	// Capture settings - flattened
	CaptureBodyEnabled     bool   `json:"capture_body_enabled"`
	CaptureHeadersEnabled  bool   `json:"capture_headers_enabled"`
	MaxBodySize            int64  `json:"max_body_size"`
	InspectionLevel        string `json:"inspection_level"`
	FilterApplied          string `json:"filter_applied,omitempty"`

	// Additional metadata for database optimization
	PartitionDate   string `json:"partition_date"` // YYYY-MM-DD for partitioning
	SHA256Hash      string `json:"sha256_hash"`   // Hash of entire record for deduplication
}

// ToNormalizedCapture converts an EnhancedCapture to NormalizedCapture format
func ToNormalizedCapture(enhanced *EnhancedCapture) *NormalizedCapture {
	normalized := &NormalizedCapture{
		// Core identifiers
		ID:            enhanced.ID,
		CorrelationID: enhanced.CorrelationID,
		SessionID:     enhanced.SessionID,
		Timestamp:     enhanced.Timestamp,

		// Connection data
		ClientIP:   enhanced.Connection.ClientIP,
		ClientPort: enhanced.Connection.ClientPort,
		ServerIP:   enhanced.Connection.ServerIP,
		ServerPort: enhanced.Connection.ServerPort,
		Protocol:   enhanced.Connection.Protocol,
		TLSVersion: enhanced.Connection.TLSVersion,
		Cipher:     enhanced.Connection.Cipher,
		Domain:     enhanced.Connection.Domain,
		SNI:        enhanced.Connection.SNI,

		// Request data
		RequestMethod:      enhanced.Request.Method,
		RequestURL:         enhanced.Request.URL,
		RequestPath:        enhanced.Request.Path,
		RequestQuery:       enhanced.Request.Query,
		RequestHTTPVersion: enhanced.Request.HTTPVersion,
		RequestContentType: enhanced.Request.ContentType,
		RequestUserAgent:   enhanced.Request.UserAgent,
		RequestReferer:     enhanced.Request.Referer,
		RequestBodySize:    enhanced.Request.BodySize,

		// Response data
		ResponseStatusCode:    enhanced.Response.StatusCode,
		ResponseStatusText:    enhanced.Response.StatusText,
		ResponseContentType:   enhanced.Response.ContentType,
		ResponseContentLength: enhanced.Response.ContentLength,
		ResponseBodySize:      enhanced.Response.BodySize,
		ResponseTimestamp:     enhanced.Timestamp.Add(enhanced.Response.ProcessingTime), // Add processing time to request timestamp

		// Timing data
		DurationMs:       int64(enhanced.Duration / time.Millisecond),
		ProcessingTimeMs: int64(enhanced.Response.ProcessingTime / time.Millisecond),
		StartTime:        enhanced.StartTime,
		EndTime:          enhanced.EndTime,

		// Classification
		ResourceType: string(enhanced.ResourceType),
		Category:     enhanced.Category,
		Tags:         enhanced.Tags,
		IsEncrypted:  enhanced.Connection.TLSVersion != "",

		// Status classifications
		IsSuccessful:  enhanced.Response.StatusCode >= 200 && enhanced.Response.StatusCode < 300,
		IsClientError: enhanced.Response.StatusCode >= 400 && enhanced.Response.StatusCode < 500,
		IsServerError: enhanced.Response.StatusCode >= 500,

		// Performance classifications
		IsSlowRequest:   enhanced.Duration > 5*time.Second,
		IsLargeResponse: enhanced.Response.BodySize > 1024*1024, // > 1MB

		// Capture settings
		CaptureBodyEnabled:    enhanced.CaptureSettings.CaptureBody,
		CaptureHeadersEnabled: enhanced.CaptureSettings.CaptureHeaders,
		MaxBodySize:           enhanced.CaptureSettings.MaxBodySize,
		InspectionLevel:       enhanced.CaptureSettings.InspectionLevel,
		FilterApplied:         enhanced.CaptureSettings.FilterApplied,

		// Database optimization fields
		PartitionDate: enhanced.Timestamp.Format("2006-01-02"),
	}

	// Handle identity data
	if enhanced.Identity != nil && enhanced.Identity.PrimaryIdentity != nil {
		normalized.IdentityID = enhanced.Identity.PrimaryIdentity.ID
		normalized.IdentityType = string(enhanced.Identity.PrimaryIdentity.Type)
		normalized.IdentityConfidence = enhanced.Identity.PrimaryIdentity.Confidence
		normalized.IsIdentified = true

		// Extract metadata flags
		if isPrivate, ok := enhanced.Identity.PrimaryIdentity.Metadata["is_private"].(bool); ok {
			normalized.IsPrivateNetwork = isPrivate
		}
		if isTrusted, ok := enhanced.Identity.PrimaryIdentity.Metadata["is_trusted"].(bool); ok {
			normalized.IsTrusted = isTrusted
		}
	}

	// Normalize and extract important headers (with sensitive data redaction)
	normalized.ImportantHeaders = NormalizeHeaders(enhanced.Request.Headers, enhanced.Response.Headers)
	normalized.HeaderCount = len(enhanced.Request.Headers) + len(enhanced.Response.Headers)

	// Generate body previews and hashes with sensitive data redaction
	_, redactedRequestBody := redactSensitiveData(nil, enhanced.Request.Body)
	_, redactedResponseBody := redactSensitiveData(nil, enhanced.Response.Body)
	
	normalized.RequestBodyPreview = generateBodyPreview(redactedRequestBody)
	normalized.RequestBodyHash = generateBodyHash(enhanced.Request.Body) // Hash original for integrity
	normalized.ResponseBodyPreview = generateBodyPreview(redactedResponseBody)
	normalized.ResponseBodyHash = generateBodyHash(enhanced.Response.Body) // Hash original for integrity

	// Generate record hash for deduplication
	normalized.SHA256Hash = generateRecordHash(normalized)

	return normalized
}

// AutoTagCapture automatically adds intelligent tags based on request/response analysis
func AutoTagCapture(capture *EnhancedCapture) {
	if capture.Tags == nil {
		capture.Tags = make([]string, 0)
	}
	
	existingTags := make(map[string]bool)
	for _, tag := range capture.Tags {
		existingTags[tag] = true
	}
	
	// Function to add tag if not already present
	addTag := func(tag string) {
		if !existingTags[tag] {
			capture.Tags = append(capture.Tags, tag)
			existingTags[tag] = true
		}
	}
	
	// Resource type tagging
	addTag(string(capture.ResourceType))
	
	// Protocol and security tagging
	if capture.Connection.TLSVersion != "" {
		addTag("encrypted")
		addTag("tls")
		// Add specific TLS version tag
		if capture.Connection.TLSVersion != "" {
			addTag("tls_" + strings.ReplaceAll(capture.Connection.TLSVersion, ".", "_"))
		}
	} else {
		addTag("unencrypted")
		addTag("plaintext")
	}
	
	// HTTP method tagging
	if capture.Request.Method != "" {
		addTag("method_" + strings.ToLower(capture.Request.Method))
		
		// REST API method classification
		switch strings.ToUpper(capture.Request.Method) {
		case "GET":
			addTag("read_operation")
		case "POST", "PUT", "PATCH":
			addTag("write_operation")
		case "DELETE":
			addTag("delete_operation")
		case "OPTIONS":
			addTag("preflight")
		case "HEAD":
			addTag("metadata_request")
		}
	}
	
	// Status code classification
	statusCode := capture.Response.StatusCode
	if statusCode >= 200 && statusCode < 300 {
		addTag("success")
		addTag("2xx")
	} else if statusCode >= 300 && statusCode < 400 {
		addTag("redirect")
		addTag("3xx")
	} else if statusCode >= 400 && statusCode < 500 {
		addTag("client_error")
		addTag("4xx")
		
		// Specific error types
		switch statusCode {
		case 401:
			addTag("unauthorized")
		case 403:
			addTag("forbidden")
		case 404:
			addTag("not_found")
		case 429:
			addTag("rate_limited")
		}
	} else if statusCode >= 500 {
		addTag("server_error")
		addTag("5xx")
		
		// Specific server errors
		switch statusCode {
		case 500:
			addTag("internal_error")
		case 502:
			addTag("bad_gateway")
		case 503:
			addTag("service_unavailable")
		case 504:
			addTag("gateway_timeout")
		}
	}
	
	// Performance tagging
	if capture.Duration > 10*time.Second {
		addTag("very_slow")
	} else if capture.Duration > 5*time.Second {
		addTag("slow")
	} else if capture.Duration > 1*time.Second {
		addTag("moderate")
	} else if capture.Duration < 100*time.Millisecond {
		addTag("fast")
	}
	
	// Size tagging
	totalBodySize := capture.Request.BodySize + capture.Response.BodySize
	if totalBodySize > 10*1024*1024 { // > 10MB
		addTag("very_large")
	} else if totalBodySize > 1024*1024 { // > 1MB
		addTag("large")
	} else if totalBodySize < 1024 { // < 1KB
		addTag("small")
	}
	
	// Content type analysis
	requestContentType := strings.ToLower(capture.Request.ContentType)
	responseContentType := strings.ToLower(capture.Response.ContentType)
	
	// Request content type tags
	if strings.Contains(requestContentType, "json") {
		addTag("json_request")
		addTag("api_call")
	} else if strings.Contains(requestContentType, "xml") {
		addTag("xml_request")
		addTag("api_call")
	} else if strings.Contains(requestContentType, "form") {
		addTag("form_submission")
		if strings.Contains(requestContentType, "multipart") {
			addTag("file_upload")
		}
	}
	
	// Response content type tags
	if strings.Contains(responseContentType, "json") {
		addTag("json_response")
		addTag("api_response")
	} else if strings.Contains(responseContentType, "xml") {
		addTag("xml_response")
		addTag("api_response")
	} else if strings.Contains(responseContentType, "html") {
		addTag("html_page")
		addTag("web_page")
	} else if strings.Contains(responseContentType, "image") {
		addTag("image_resource")
	} else if strings.Contains(responseContentType, "javascript") {
		addTag("script_resource")
	} else if strings.Contains(responseContentType, "css") {
		addTag("style_resource")
	}
	
	// Identity-based tagging
	if capture.Identity != nil && capture.Identity.PrimaryIdentity != nil {
		addTag("identified")
		addTag("identity_" + string(capture.Identity.PrimaryIdentity.Type))
		
		// Confidence level tags
		confidence := capture.Identity.PrimaryIdentity.Confidence
		if confidence >= 0.9 {
			addTag("high_confidence")
		} else if confidence >= 0.7 {
			addTag("medium_confidence")
		} else {
			addTag("low_confidence")
		}
		
		// Network context tags
		if metadata := capture.Identity.PrimaryIdentity.Metadata; metadata != nil {
			if isPrivate, ok := metadata["is_private"].(bool); ok && isPrivate {
				addTag("private_network")
			}
			if isTrusted, ok := metadata["is_trusted"].(bool); ok && isTrusted {
				addTag("trusted_source")
			}
		}
	} else {
		addTag("anonymous")
		addTag("unidentified")
	}
	
	// Domain and path analysis
	domain := strings.ToLower(capture.Connection.Domain)
	path := strings.ToLower(capture.Request.Path)
	
	// Common domain patterns
	if strings.Contains(domain, "api.") || strings.Contains(domain, ".api.") {
		addTag("api_subdomain")
	}
	if strings.Contains(domain, "cdn.") || strings.Contains(domain, ".cdn.") {
		addTag("cdn_resource")
	}
	if strings.Contains(domain, "static.") || strings.Contains(domain, ".static.") {
		addTag("static_resource")
	}
	
	// Common path patterns
	if strings.HasPrefix(path, "/api/") {
		addTag("api_endpoint")
	}
	if strings.Contains(path, "/admin/") {
		addTag("admin_area")
	}
	if strings.Contains(path, "/auth/") || strings.Contains(path, "/login/") {
		addTag("authentication")
	}
	if strings.Contains(path, "/upload/") || strings.Contains(path, "/file/") {
		addTag("file_operation")
	}
	if strings.Contains(path, "/search/") || strings.Contains(path, "/query/") {
		addTag("search_operation")
	}
	
	// User-Agent analysis
	userAgent := strings.ToLower(capture.Request.UserAgent)
	if strings.Contains(userAgent, "bot") || strings.Contains(userAgent, "crawler") || strings.Contains(userAgent, "spider") {
		addTag("bot_traffic")
	}
	if strings.Contains(userAgent, "mobile") || strings.Contains(userAgent, "android") || strings.Contains(userAgent, "iphone") {
		addTag("mobile_client")
	}
	if strings.Contains(userAgent, "curl") || strings.Contains(userAgent, "wget") || strings.Contains(userAgent, "python") {
		addTag("automated_client")
	}
	
	// Security-related analysis
	if capture.Request.Headers != nil {
		// Check for common security headers
		if _, hasAuth := capture.Request.Headers["Authorization"]; hasAuth {
			addTag("authenticated_request")
		}
		if _, hasCookie := capture.Request.Headers["Cookie"]; hasCookie {
			addTag("session_cookie")
		}
		if origin, hasOrigin := capture.Request.Headers["Origin"]; hasOrigin && origin != "" {
			addTag("cors_request")
		}
		if xRequestedWith, hasXRW := capture.Request.Headers["X-Requested-With"]; hasXRW && xRequestedWith == "XMLHttpRequest" {
			addTag("ajax_request")
		}
	}
	
	// Time-based tagging
	hour := capture.Timestamp.Hour()
	if hour >= 0 && hour < 6 {
		addTag("night_traffic")
	} else if hour >= 6 && hour < 12 {
		addTag("morning_traffic")
	} else if hour >= 12 && hour < 18 {
		addTag("afternoon_traffic")
	} else {
		addTag("evening_traffic")
	}
	
	// Weekend vs weekday
	weekday := capture.Timestamp.Weekday()
	if weekday == time.Saturday || weekday == time.Sunday {
		addTag("weekend_traffic")
	} else {
		addTag("weekday_traffic")
	}
}

// ClassifyCapture adds classification tags and metadata to a capture
func ClassifyCapture(capture *EnhancedCapture) {
	tags := make([]string, 0)
	metadata := make(map[string]interface{})

	// Add resource type tag
	tags = append(tags, string(capture.ResourceType))

	// Add protocol tags
	if capture.Connection.TLSVersion != "" {
		tags = append(tags, "encrypted")
		metadata["tls_version"] = capture.Connection.TLSVersion
	} else {
		tags = append(tags, "unencrypted")
	}

	// Add identity tags if available
	if capture.Identity != nil && capture.Identity.PrimaryIdentity != nil {
		tags = append(tags, "identified")
		metadata["identity_type"] = capture.Identity.PrimaryIdentity.Type
		metadata["identity_confidence"] = capture.Identity.PrimaryIdentity.Confidence

		// Add network context tags
		if identityMeta, ok := capture.Identity.PrimaryIdentity.Metadata["is_private"].(bool); ok && identityMeta {
			tags = append(tags, "private_network")
		}
		if identityMeta, ok := capture.Identity.PrimaryIdentity.Metadata["is_trusted"].(bool); ok && identityMeta {
			tags = append(tags, "trusted")
		}
	} else {
		tags = append(tags, "anonymous")
	}

	// Add status code tags
	if capture.Response.StatusCode >= 200 && capture.Response.StatusCode < 300 {
		tags = append(tags, "success")
	} else if capture.Response.StatusCode >= 400 && capture.Response.StatusCode < 500 {
		tags = append(tags, "client_error")
	} else if capture.Response.StatusCode >= 500 {
		tags = append(tags, "server_error")
	}

	// Add timing tags
	if capture.Duration > 5*time.Second {
		tags = append(tags, "slow")
	} else if capture.Duration < 100*time.Millisecond {
		tags = append(tags, "fast")
	}

	// Add size tags
	if capture.Response.BodySize > 1024*1024 { // > 1MB
		tags = append(tags, "large_response")
	}

	capture.Tags = tags
	if capture.Metadata == nil {
		capture.Metadata = metadata
	} else {
		for k, v := range metadata {
			capture.Metadata[k] = v
		}
	}
}
