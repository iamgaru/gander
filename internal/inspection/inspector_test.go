package inspection

import (
	"net/http"
	"testing"

	"github.com/iamgaru/gander/internal/config"
)

func TestContentInspector_ShouldInspect(t *testing.T) {
	// Create test configuration
	cfg := &config.InspectionConfig{
		GlobalRules: config.InspectionRules{
			AlwaysInspect: []string{
				"text/html",
				"application/javascript",
			},
			ConditionalInspect: []string{
				"image/jpeg",
				"image/png",
			},
			NeverInspect: []string{
				"application/octet-stream",
				"video/mp4",
			},
			SizeLimits: config.SizeLimitsConfig{
				MaxInspectSize: "10MB",
				ImageMaxSize:   "5MB",
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
					MaxInspectSize: "1MB",
				},
				URLPatterns: config.URLPatternsConfig{
					ForceInspect: []string{},
					ForceSkip:    []string{},
				},
			},
		},
	}

	inspector := NewContentInspector(cfg)

	tests := []struct {
		name        string
		context     *InspectionContext
		expected    Decision
		description string
	}{
		{
			name: "HTML should be inspected",
			context: &InspectionContext{
				URL:         "https://example.com/index.html",
				Domain:      "example.com",
				ContentType: "text/html",
				ContentSize: 1024,
			},
			expected:    DecisionInspect,
			description: "HTML is in always inspect list",
		},
		{
			name: "JavaScript should be inspected",
			context: &InspectionContext{
				URL:         "https://example.com/app.js",
				Domain:      "example.com",
				ContentType: "application/javascript",
				ContentSize: 1024,
			},
			expected:    DecisionInspect,
			description: "JavaScript is in always inspect list",
		},
		{
			name: "Binary data should be skipped",
			context: &InspectionContext{
				URL:         "https://example.com/file.bin",
				Domain:      "example.com",
				ContentType: "application/octet-stream",
				ContentSize: 1024,
			},
			expected:    DecisionSkip,
			description: "Binary data is in never inspect list",
		},
		{
			name: "Small image should be inspected",
			context: &InspectionContext{
				URL:         "https://example.com/image.jpg",
				Domain:      "example.com",
				ContentType: "image/jpeg",
				ContentSize: 1024, // 1KB
			},
			expected:    DecisionInspect,
			description: "Small image passes size check",
		},
		{
			name: "Large image should be skipped",
			context: &InspectionContext{
				URL:         "https://example.com/large.jpg",
				Domain:      "example.com",
				ContentType: "image/jpeg",
				ContentSize: 10 * 1024 * 1024, // 10MB
			},
			expected:    DecisionSkip,
			description: "Large image exceeds size limit",
		},
		{
			name: "YouTube video should be skipped",
			context: &InspectionContext{
				URL:         "https://www.youtube.com/watch?v=test",
				Domain:      "www.youtube.com",
				ContentType: "video/mp4",
				ContentSize: 1024,
			},
			expected:    DecisionSkip,
			description: "YouTube video is in domain-specific never inspect list",
		},
		{
			name: "YouTube HTML should be inspected",
			context: &InspectionContext{
				URL:         "https://www.youtube.com/watch?v=test",
				Domain:      "www.youtube.com",
				ContentType: "text/html",
				ContentSize: 1024,
			},
			expected:    DecisionInspect,
			description: "YouTube HTML is in domain-specific always inspect list",
		},
		{
			name: "Unknown content type should be skipped",
			context: &InspectionContext{
				URL:         "https://example.com/unknown.xyz",
				Domain:      "example.com",
				ContentType: "application/unknown",
				ContentSize: 1024,
			},
			expected:    DecisionSkip,
			description: "Unknown content type defaults to skip",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision := inspector.ShouldInspect(tt.context)
			if decision != tt.expected {
				t.Errorf("ShouldInspect() = %v, expected %v (%s)", decision, tt.expected, tt.description)
			}
		})
	}
}

func TestContentInspector_InspectContent(t *testing.T) {
	cfg := &config.InspectionConfig{
		GlobalRules: config.InspectionRules{
			AlwaysInspect: []string{"text/html"},
			NeverInspect:  []string{"application/octet-stream"},
			SizeLimits: config.SizeLimitsConfig{
				StreamingInspectBytes: "4KB",
			},
			URLPatterns: config.URLPatternsConfig{
				ForceInspect: []string{},
				ForceSkip:    []string{},
			},
		},
		AIPreparation: config.AIPreparationConfig{
			Enabled:           true,
			SupportedAnalysis: []string{"image_ocr"},
		},
	}

	inspector := NewContentInspector(cfg)

	ctx := &InspectionContext{
		URL:         "https://example.com/index.html",
		Domain:      "example.com",
		ContentType: "text/html",
		ContentSize: 1024,
		Headers:     make(http.Header),
		IsStreaming: false,
	}

	result := inspector.InspectContent(ctx)

	if result.Decision != DecisionInspect {
		t.Errorf("InspectContent() decision = %v, expected %v", result.Decision, DecisionInspect)
	}

	if result.Reason == "" {
		t.Error("InspectContent() should provide a reason")
	}
}

func TestStreamingInspector(t *testing.T) {
	cfg := &config.InspectionConfig{
		GlobalRules: config.InspectionRules{
			SizeLimits: config.SizeLimitsConfig{
				StreamingInspectBytes: "10B", // 10 bytes for testing
			},
			URLPatterns: config.URLPatternsConfig{
				ForceInspect: []string{},
				ForceSkip:    []string{},
			},
		},
	}

	inspector := NewContentInspector(cfg)

	ctx := &InspectionContext{
		URL:         "https://example.com/stream",
		Domain:      "example.com",
		ContentType: "application/json",
		ContentSize: -1, // Unknown size
		IsStreaming: true,
	}

	streamInspector := inspector.NewStreamingInspector(ctx)

	// Write some test data
	testData := []byte("This is a test streaming content that is longer than 10 bytes")
	
	n, err := streamInspector.Write(testData)
	if err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	
	if n != len(testData) {
		t.Errorf("Write() returned %d, expected %d", n, len(testData))
	}

	if !streamInspector.IsDone() {
		t.Error("StreamingInspector should be done after writing data larger than inspect size")
	}

	collected := streamInspector.GetCollectedData()
	if len(collected) != 10 {
		t.Errorf("GetCollectedData() returned %d bytes, expected 10", len(collected))
	}

	expected := "This is a "
	if string(collected) != expected {
		t.Errorf("GetCollectedData() = %q, expected %q", string(collected), expected)
	}
}

func TestParseSize(t *testing.T) {
	tests := []struct {
		input    string
		expected int64
	}{
		{"1024", 1024},
		{"1024B", 1024},
		{"1KB", 1024},
		{"1MB", 1024 * 1024},
		{"1GB", 1024 * 1024 * 1024},
		{"1.5KB", 1536},
		{"", 0},
		{"invalid", 0},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := parseSize(tt.input)
			if result != tt.expected {
				t.Errorf("parseSize(%q) = %d, expected %d", tt.input, result, tt.expected)
			}
		})
	}
}

func TestDecisionString(t *testing.T) {
	tests := []struct {
		decision Decision
		expected string
	}{
		{DecisionSkip, "skip"},
		{DecisionInspect, "inspect"},
		{DecisionConditional, "conditional"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := tt.decision.String()
			if result != tt.expected {
				t.Errorf("Decision.String() = %q, expected %q", result, tt.expected)
			}
		})
	}
}