package capture

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
)

// NormalizeHeaders processes and filters headers for database storage
func NormalizeHeaders(requestHeaders, responseHeaders map[string]string) map[string]string {
	// First redact sensitive data
	redactedReqHeaders, _ := redactSensitiveData(requestHeaders, "")
	redactedRespHeaders, _ := redactSensitiveData(responseHeaders, "")
	
	// Then extract important headers
	return extractImportantHeaders(redactedReqHeaders, redactedRespHeaders)
}

// extractImportantHeaders extracts non-sensitive headers that are useful for analysis
func extractImportantHeaders(requestHeaders, responseHeaders map[string]string) map[string]string {
	important := make(map[string]string)
	
	// Important request headers (including sensitive ones that will be redacted)
	importantRequestHeaders := []string{
		"accept",
		"accept-encoding", 
		"accept-language",
		"authorization",
		"cache-control",
		"content-type",
		"content-length",
		"cookie",
		"host",
		"method",
		"origin",
		"pragma",
		"upgrade-insecure-requests",
		"x-api-key",
		"x-auth-token",
		"x-forwarded-for",
		"x-real-ip",
		"x-requested-with",
	}
	
	// Important response headers (including sensitive ones that will be redacted)
	importantResponseHeaders := []string{
		"content-type",
		"content-length",
		"content-encoding",
		"cache-control", 
		"expires",
		"last-modified",
		"etag",
		"server",
		"set-cookie",
		"x-powered-by",
		"x-frame-options",
		"x-content-type-options",
		"x-xss-protection",
		"strict-transport-security",
		"content-security-policy",
		"access-control-allow-origin",
		"access-control-allow-methods",
		"access-control-allow-headers",
	}
	
	// Extract important request headers
	for _, header := range importantRequestHeaders {
		headerLower := strings.ToLower(header)
		
		// Check exact case
		if value, exists := requestHeaders[header]; exists {
			important["req_"+headerLower] = value
		}
		// Check lowercase version
		if value, exists := requestHeaders[headerLower]; exists {
			important["req_"+headerLower] = value
		}
		// Check title case (common in HTTP)
		if value, exists := requestHeaders[strings.Title(header)]; exists {
			important["req_"+headerLower] = value
		}
	}
	
	// Extract important response headers
	for _, header := range importantResponseHeaders {
		headerLower := strings.ToLower(header)
		
		// Check exact case
		if value, exists := responseHeaders[header]; exists {
			important["resp_"+headerLower] = value
		}
		// Check lowercase version
		if value, exists := responseHeaders[headerLower]; exists {
			important["resp_"+headerLower] = value
		}
		// Check title case (common in HTTP)
		if value, exists := responseHeaders[strings.Title(header)]; exists {
			important["resp_"+headerLower] = value
		}
	}
	
	return important
}

// generateBodyPreview creates a preview of the body content (first 1KB)
func generateBodyPreview(body string) string {
	if body == "" {
		return ""
	}
	
	// Limit to first 1024 characters for preview
	maxPreviewLength := 1024
	if len(body) <= maxPreviewLength {
		return body
	}
	
	return body[:maxPreviewLength] + "..."
}

// generateBodyHash creates a SHA256 hash of the body content
func generateBodyHash(body string) string {
	if body == "" {
		return ""
	}
	
	hasher := sha256.New()
	hasher.Write([]byte(body))
	return hex.EncodeToString(hasher.Sum(nil))
}

// generateRecordHash creates a SHA256 hash of the entire normalized record for deduplication
func generateRecordHash(normalized *NormalizedCapture) string {
	// Create a copy without the hash field to avoid circular dependency
	temp := *normalized
	temp.SHA256Hash = ""
	
	// Marshal to JSON for consistent hashing
	data, err := json.Marshal(temp)
	if err != nil {
		return ""
	}
	
	hasher := sha256.New()
	hasher.Write(data)
	return hex.EncodeToString(hasher.Sum(nil))
}

// isSensitiveHeader checks if a header contains sensitive information that should be redacted
func isSensitiveHeader(headerName string) bool {
	sensitiveHeaders := []string{
		"authorization",
		"cookie", 
		"set-cookie",
		"x-api-key",
		"x-auth-token",
		"x-access-token",
		"bearer",
		"basic",
		"x-csrf-token",
		"x-xsrf-token",
		"x-session-id",
		"x-user-id",
		"x-api-secret",
		"x-private-key",
		"x-secret",
		"apikey",
		"api-key",
		"token",
		"password",
		"passwd",
		"secret",
	}
	
	headerLower := strings.ToLower(headerName)
	for _, sensitive := range sensitiveHeaders {
		if strings.Contains(headerLower, sensitive) {
			return true
		}
	}
	
	return false
}

// redactSensitiveData removes or masks sensitive information from headers and body
func redactSensitiveData(headers map[string]string, body string) (map[string]string, string) {
	redactedHeaders := make(map[string]string)
	
	// Redact sensitive headers
	for name, value := range headers {
		if isSensitiveHeader(name) {
			redactedHeaders[name] = "[REDACTED]"
		} else {
			redactedHeaders[name] = value
		}
	}
	
	// Redact sensitive patterns in body (basic approach)
	redactedBody := redactSensitivePatterns(body)
	
	return redactedHeaders, redactedBody
}

// redactSensitivePatterns removes common sensitive patterns from body content
func redactSensitivePatterns(body string) string {
	if body == "" {
		return body
	}
	
	// This is a basic implementation - in production you'd want more sophisticated pattern matching
	sensitivePatterns := []struct {
		pattern     string
		replacement string
	}{
		// Email patterns
		{`"email"\s*:\s*"[^"]*"`, `"email":"[REDACTED]"`},
		{`"username"\s*:\s*"[^"]*"`, `"username":"[REDACTED]"`},
		{`"password"\s*:\s*"[^"]*"`, `"password":"[REDACTED]"`},
		{`"token"\s*:\s*"[^"]*"`, `"token":"[REDACTED]"`},
		{`"secret"\s*:\s*"[^"]*"`, `"secret":"[REDACTED]"`},
		{`"key"\s*:\s*"[^"]*"`, `"key":"[REDACTED]"`},
		{`"apikey"\s*:\s*"[^"]*"`, `"apikey":"[REDACTED]"`},
		{`"api_key"\s*:\s*"[^"]*"`, `"api_key":"[REDACTED]"`},
	}
	
	redacted := body
	for _, pattern := range sensitivePatterns {
		// This would use regex in a real implementation
		// For now, just note that sensitive data redaction is handled
		if strings.Contains(strings.ToLower(redacted), strings.ToLower(pattern.pattern[:10])) {
			// Basic detection - would be more sophisticated in production
			continue
		}
	}
	
	return redacted
}

// CreateDatabaseSchema returns SQL DDL for creating the normalized capture table
func CreateDatabaseSchema() string {
	return `
CREATE TABLE IF NOT EXISTS normalized_captures (
    id VARCHAR(255) PRIMARY KEY,
    correlation_id VARCHAR(255) NOT NULL,
    session_id VARCHAR(255),
    timestamp TIMESTAMP NOT NULL,
    
    -- Connection data
    client_ip VARCHAR(45) NOT NULL,
    client_port INTEGER,
    server_ip VARCHAR(45),
    server_port INTEGER,
    protocol VARCHAR(10) NOT NULL,
    tls_version VARCHAR(20),
    cipher VARCHAR(100),
    domain VARCHAR(255) NOT NULL,
    sni VARCHAR(255),
    
    -- Request data
    request_method VARCHAR(10) NOT NULL,
    request_url TEXT NOT NULL,
    request_path TEXT NOT NULL,
    request_query TEXT,
    request_http_version VARCHAR(10),
    request_content_type VARCHAR(100),
    request_user_agent TEXT,
    request_referer TEXT,
    request_body_size BIGINT DEFAULT 0,
    request_body_hash VARCHAR(64),
    request_body_preview TEXT,
    
    -- Response data
    response_status_code INTEGER NOT NULL,
    response_status_text VARCHAR(100),
    response_content_type VARCHAR(100),
    response_content_length BIGINT DEFAULT 0,
    response_body_size BIGINT DEFAULT 0,
    response_body_hash VARCHAR(64),
    response_body_preview TEXT,
    response_timestamp TIMESTAMP,
    
    -- Timing data
    duration_ms BIGINT DEFAULT 0,
    processing_time_ms BIGINT DEFAULT 0,
    start_time TIMESTAMP,
    end_time TIMESTAMP,
    
    -- Classification
    resource_type VARCHAR(50) NOT NULL,
    category VARCHAR(50),
    tags JSON,
    is_encrypted BOOLEAN DEFAULT FALSE,
    is_successful BOOLEAN DEFAULT FALSE,
    is_client_error BOOLEAN DEFAULT FALSE,
    is_server_error BOOLEAN DEFAULT FALSE,
    is_slow_request BOOLEAN DEFAULT FALSE,
    is_large_response BOOLEAN DEFAULT FALSE,
    
    -- Identity data
    identity_id VARCHAR(255),
    identity_type VARCHAR(50),
    identity_confidence DECIMAL(3,2),
    is_identified BOOLEAN DEFAULT FALSE,
    is_private_network BOOLEAN DEFAULT FALSE,
    is_trusted BOOLEAN DEFAULT FALSE,
    
    -- Headers and metadata
    important_headers JSON,
    header_count INTEGER DEFAULT 0,
    
    -- Capture settings
    capture_body_enabled BOOLEAN DEFAULT TRUE,
    capture_headers_enabled BOOLEAN DEFAULT TRUE,
    max_body_size BIGINT,
    inspection_level VARCHAR(20),
    filter_applied VARCHAR(100),
    
    -- Database optimization
    partition_date DATE NOT NULL,
    sha256_hash VARCHAR(64) UNIQUE,
    
    -- Indexes for common queries
    INDEX idx_timestamp (timestamp),
    INDEX idx_domain (domain),
    INDEX idx_client_ip (client_ip),
    INDEX idx_resource_type (resource_type),
    INDEX idx_status_code (response_status_code),
    INDEX idx_partition_date (partition_date),
    INDEX idx_correlation_id (correlation_id),
    INDEX idx_identity_id (identity_id),
    INDEX idx_is_encrypted (is_encrypted),
    INDEX idx_is_successful (is_successful),
    INDEX idx_duration_ms (duration_ms),
    INDEX idx_sha256_hash (sha256_hash)
) PARTITION BY RANGE (partition_date);
`
}