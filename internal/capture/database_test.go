package capture

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/iamgaru/gander/internal/identity"
)

// TestNormalizedCaptureFormat tests the normalized capture format for database compatibility
func TestNormalizedCaptureFormat(t *testing.T) {
	// Create a sample enhanced capture
	enhanced := createSampleEnhancedCapture()

	// Convert to normalized format
	normalized := ToNormalizedCapture(enhanced)

	// Test core fields are present
	if normalized.ID == "" {
		t.Error("ID should not be empty")
	}
	if normalized.CorrelationID == "" {
		t.Error("CorrelationID should not be empty")
	}
	if normalized.Timestamp.IsZero() {
		t.Error("Timestamp should not be zero")
	}

	// Test flattened connection data
	if normalized.ClientIP == "" {
		t.Error("ClientIP should not be empty")
	}
	if normalized.Domain == "" {
		t.Error("Domain should not be empty")
	}
	if normalized.Protocol == "" {
		t.Error("Protocol should not be empty")
	}

	// Test flattened request data
	if normalized.RequestMethod == "" {
		t.Error("RequestMethod should not be empty")
	}
	if normalized.RequestURL == "" {
		t.Error("RequestURL should not be empty")
	}
	if normalized.RequestPath == "" {
		t.Error("RequestPath should not be empty")
	}

	// Test response data
	if normalized.ResponseStatusCode == 0 {
		t.Error("ResponseStatusCode should not be zero")
	}

	// Test classification flags
	if !normalized.IsEncrypted {
		t.Error("IsEncrypted should be true for HTTPS")
	}
	if !normalized.IsSuccessful {
		t.Error("IsSuccessful should be true for 200 status")
	}

	// Test partition date
	expectedDate := enhanced.Timestamp.Format("2006-01-02")
	if normalized.PartitionDate != expectedDate {
		t.Errorf("PartitionDate should be %s, got %s", expectedDate, normalized.PartitionDate)
	}

	// Test hash generation
	if normalized.SHA256Hash == "" {
		t.Error("SHA256Hash should not be empty")
	}

	// Test serialization to JSON
	jsonData, err := json.MarshalIndent(normalized, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal normalized capture: %v", err)
	}

	// Test deserialization
	var deserialized NormalizedCapture
	if err := json.Unmarshal(jsonData, &deserialized); err != nil {
		t.Fatalf("Failed to unmarshal normalized capture: %v", err)
	}

	// Verify key fields after round-trip
	if deserialized.ID != normalized.ID {
		t.Error("ID mismatch after JSON round-trip")
	}
	if deserialized.Domain != normalized.Domain {
		t.Error("Domain mismatch after JSON round-trip")
	}
	if deserialized.ResponseStatusCode != normalized.ResponseStatusCode {
		t.Error("ResponseStatusCode mismatch after JSON round-trip")
	}
}

// TestAutoTagging tests the automatic tagging functionality
func TestAutoTagging(t *testing.T) {
	enhanced := createSampleEnhancedCapture()

	// Clear existing tags
	enhanced.Tags = nil

	// Apply auto tagging
	AutoTagCapture(enhanced)

	// Verify expected tags
	expectedTags := []string{
		"api",           // resource type
		"encrypted",     // HTTPS
		"tls",           // TLS
		"method_get",    // HTTP method
		"success",       // 2xx status
		"2xx",           // status code range
		"json_response", // JSON content type
		"api_response",  // API response
		"identified",    // has identity
		"api_endpoint",  // /api/ path
	}

	tagMap := make(map[string]bool)
	for _, tag := range enhanced.Tags {
		tagMap[tag] = true
	}

	for _, expectedTag := range expectedTags {
		if !tagMap[expectedTag] {
			t.Errorf("Expected tag '%s' not found in auto-generated tags: %v", expectedTag, enhanced.Tags)
		}
	}
}

// TestHeaderNormalization tests header normalization and redaction
func TestHeaderNormalization(t *testing.T) {
	// Create headers with sensitive data
	requestHeaders := map[string]string{
		"Content-Type":    "application/json",
		"Authorization":   "Bearer secret-token-123",
		"User-Agent":      "Test Agent",
		"X-Api-Key":       "sensitive-api-key",
		"Accept":          "application/json",
		"Cookie":          "sessionid=abc123",
	}

	responseHeaders := map[string]string{
		"Content-Type":   "application/json",
		"Server":         "nginx/1.18.0",
		"Set-Cookie":     "sessionid=xyz789; HttpOnly",
		"Cache-Control":  "no-cache",
		"X-Powered-By":   "Express",
	}

	// Normalize headers
	normalized := NormalizeHeaders(requestHeaders, responseHeaders)

	// Check that important headers are preserved
	if normalized["req_content-type"] != "application/json" {
		t.Error("Important request header should be preserved")
	}
	if normalized["resp_content-type"] != "application/json" {
		t.Error("Important response header should be preserved")
	}
	if normalized["resp_server"] != "nginx/1.18.0" {
		t.Error("Server header should be preserved")
	}

	// Check that sensitive headers are redacted
	if val, exists := normalized["req_authorization"]; !exists || val != "[REDACTED]" {
		t.Errorf("Authorization header should be redacted, got: %v (exists: %v)", val, exists)
	}
	if val, exists := normalized["req_x-api-key"]; !exists || val != "[REDACTED]" {
		t.Errorf("API key header should be redacted, got: %v (exists: %v)", val, exists)
	}
	if val, exists := normalized["resp_set-cookie"]; !exists || val != "[REDACTED]" {
		t.Errorf("Set-Cookie header should be redacted, got: %v (exists: %v)", val, exists)
	}
	
	// Debug: print all normalized headers
	t.Logf("All normalized headers: %+v", normalized)
}

// TestDatabaseSchema tests that the database schema can be generated
func TestDatabaseSchema(t *testing.T) {
	schema := CreateDatabaseSchema()

	// Verify schema contains key elements
	if schema == "" {
		t.Error("Database schema should not be empty")
	}

	// Check for table creation
	if !strings.Contains(schema, "CREATE TABLE") {
		t.Error("Schema should contain CREATE TABLE statement")
	}

	// Check for key columns
	requiredColumns := []string{
		"id", "correlation_id", "timestamp", "client_ip", "domain",
		"request_method", "request_url", "response_status_code",
		"resource_type", "is_encrypted", "partition_date", "sha256_hash",
	}

	for _, column := range requiredColumns {
		if !strings.Contains(schema, column) {
			t.Errorf("Schema should contain column: %s", column)
		}
	}

	// Check for indexes
	if !strings.Contains(schema, "INDEX") {
		t.Error("Schema should contain INDEX definitions")
	}

	// Check for partitioning
	if !strings.Contains(schema, "PARTITION BY") {
		t.Error("Schema should include partitioning")
	}
}

// TestBodyProcessing tests body preview and hash generation
func TestBodyProcessing(t *testing.T) {
	// Test small body
	smallBody := `{"message": "hello world"}`
	preview := generateBodyPreview(smallBody)
	hash := generateBodyHash(smallBody)

	if preview != smallBody {
		t.Error("Small body should be returned as-is for preview")
	}
	if hash == "" {
		t.Error("Hash should be generated for body")
	}

	// Test large body
	largeBody := strings.Repeat("x", 2000)
	preview = generateBodyPreview(largeBody)
	hash = generateBodyHash(largeBody)

	if len(preview) != 1027 { // 1024 + "..."
		t.Errorf("Large body preview should be truncated to 1027 chars, got %d", len(preview))
	}
	if !strings.HasSuffix(preview, "...") {
		t.Error("Large body preview should end with '...'")
	}
	if hash == "" {
		t.Error("Hash should be generated for large body")
	}

	// Test empty body
	preview = generateBodyPreview("")
	hash = generateBodyHash("")

	if preview != "" {
		t.Error("Empty body preview should be empty")
	}
	if hash != "" {
		t.Error("Empty body hash should be empty")
	}
}

// TestRecordHashing tests record hash generation for deduplication
func TestRecordHashing(t *testing.T) {
	enhanced := createSampleEnhancedCapture()
	normalized1 := ToNormalizedCapture(enhanced)
	normalized2 := ToNormalizedCapture(enhanced)

	// Same data should produce same hash
	if normalized1.SHA256Hash != normalized2.SHA256Hash {
		t.Error("Identical records should produce identical hashes")
	}

	// Different data should produce different hashes
	enhanced.Request.Path = "/different/path"
	normalized3 := ToNormalizedCapture(enhanced)

	if normalized1.SHA256Hash == normalized3.SHA256Hash {
		t.Error("Different records should produce different hashes")
	}
}

// Helper function to create a sample enhanced capture for testing
func createSampleEnhancedCapture() *EnhancedCapture {
	now := time.Now()

	return &EnhancedCapture{
		ID:            "test-capture-123",
		CorrelationID: "test-correlation-456",
		Timestamp:     now,

		Identity: &identity.IdentityContext{
			PrimaryIdentity: &identity.Identity{
				ID:         "test-identity",
				Type:       "ip_mac",
				Confidence: 0.95,
				Metadata: map[string]interface{}{
					"is_private": true,
					"is_trusted": true,
				},
			},
		},

		Connection: ConnectionMetadata{
			ClientIP:   "192.168.1.100",
			ClientPort: 54321,
			ServerIP:   "10.0.0.1",
			ServerPort: 443,
			Protocol:   "HTTPS",
			TLSVersion: "TLS 1.3",
			Cipher:     "TLS_AES_256_GCM_SHA384",
			StartTime:  now,
			Domain:     "api.example.com",
			SNI:        "api.example.com",
		},

		Request: RequestData{
			Method:      "GET",
			URL:         "https://api.example.com/api/v1/users",
			Path:        "/api/v1/users",
			Query:       "limit=10",
			HTTPVersion: "HTTP/2.0",
			Headers: map[string]string{
				"Content-Type": "application/json",
				"User-Agent":   "Test Client/1.0",
				"Accept":       "application/json",
			},
			Body:        "",
			BodySize:    0,
			ContentType: "application/json",
			UserAgent:   "Test Client/1.0",
		},

		Response: ResponseData{
			StatusCode:     200,
			StatusText:     "OK",
			Headers: map[string]string{
				"Content-Type": "application/json",
				"Server":       "nginx/1.18.0",
			},
			Body:           `{"users": [{"id": 1, "name": "John"}]}`,
			BodySize:       35,
			ContentType:    "application/json",
			ContentLength:  35,
			ProcessingTime: 150 * time.Millisecond,
		},

		ResourceType: ResourceAPI,
		Category:     "api",
		Duration:     150 * time.Millisecond,
		StartTime:    now,
		EndTime:      now.Add(150 * time.Millisecond),

		CaptureSettings: CaptureSettings{
			CaptureBody:     true,
			MaxBodySize:     1024 * 1024,
			CaptureHeaders:  true,
			InspectionLevel: "basic",
		},
	}
}