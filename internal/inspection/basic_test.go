package inspection

import (
	"testing"

	"github.com/iamgaru/gander/internal/config"
)

func TestBasicInspection(t *testing.T) {
	// Test basic configuration creation
	cfg := &config.InspectionConfig{
		GlobalRules: config.InspectionRules{
			AlwaysInspect: []string{"text/html"},
			NeverInspect:  []string{"application/octet-stream"},
			SizeLimits: config.SizeLimitsConfig{
				MaxInspectSize: "10MB",
			},
			URLPatterns: config.URLPatternsConfig{
				ForceInspect: []string{},
				ForceSkip:    []string{},
			},
		},
	}

	inspector := NewContentInspector(cfg)
	if inspector == nil {
		t.Fatal("NewContentInspector returned nil")
	}

	// Test HTML content
	ctx := &InspectionContext{
		URL:         "https://example.com/test.html",
		Domain:      "example.com",
		ContentType: "text/html",
		ContentSize: 1024,
	}

	decision := inspector.ShouldInspect(ctx)
	if decision != DecisionInspect {
		t.Errorf("HTML should be inspected, got %v", decision)
	}

	// Test binary content
	ctx2 := &InspectionContext{
		URL:         "https://example.com/test.bin",
		Domain:      "example.com",
		ContentType: "application/octet-stream",
		ContentSize: 1024,
	}

	decision2 := inspector.ShouldInspect(ctx2)
	if decision2 != DecisionSkip {
		t.Errorf("Binary should be skipped, got %v", decision2)
	}
}

func TestParseSizeBasic(t *testing.T) {
	tests := []struct {
		input    string
		expected int64
	}{
		{"1024", 1024},
		{"1KB", 1024},
		{"1MB", 1024 * 1024},
		{"", 0},
	}

	for _, tt := range tests {
		result := parseSize(tt.input)
		if result != tt.expected {
			t.Errorf("parseSize(%q) = %d, expected %d", tt.input, result, tt.expected)
		}
	}
}

func TestDecisionStringBasic(t *testing.T) {
	if DecisionSkip.String() != "skip" {
		t.Errorf("DecisionSkip.String() = %q, expected %q", DecisionSkip.String(), "skip")
	}
	if DecisionInspect.String() != "inspect" {
		t.Errorf("DecisionInspect.String() = %q, expected %q", DecisionInspect.String(), "inspect")
	}
	if DecisionConditional.String() != "conditional" {
		t.Errorf("DecisionConditional.String() = %q, expected %q", DecisionConditional.String(), "conditional")
	}
}
