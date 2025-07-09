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
