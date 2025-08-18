package analysis

import (
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"
)

// TestFilterAction tests the FilterAction type and methods
func TestFilterAction(t *testing.T) {
	tests := []struct {
		action   FilterAction
		expected string
	}{
		{ActionAllow, "allow"},
		{ActionBlock, "block"},
		{ActionRedirect, "redirect"},
		{ActionPass, "pass"},
	}

	for _, test := range tests {
		t.Run(string(test.action), func(t *testing.T) {
			if test.action.String() != test.expected {
				t.Errorf("Expected %s, got %s", test.expected, test.action.String())
			}
		})
	}
}

// TestFilterDecision tests the FilterDecision struct
func TestFilterDecision(t *testing.T) {
	decision := FilterDecision{
		Action:    ActionBlock,
		Reason:    "Domain in blocklist",
		Target:    "",
		Metadata:  map[string]interface{}{"rule": "malware.com"},
		BlockPage: "<html>Blocked</html>",
	}

	if decision.Action != ActionBlock {
		t.Errorf("Expected action to be %s, got %s", ActionBlock, decision.Action)
	}

	if decision.Reason != "Domain in blocklist" {
		t.Errorf("Expected reason 'Domain in blocklist', got '%s'", decision.Reason)
	}

	if rule, ok := decision.Metadata["rule"]; !ok || rule != "malware.com" {
		t.Errorf("Expected metadata rule 'malware.com', got %v", rule)
	}
}

// TestFilterContext tests the FilterContext struct
func TestFilterContext(t *testing.T) {
	testURL, _ := url.Parse("https://example.com/path?query=value")
	headers := make(http.Header)
	headers.Set("User-Agent", "Mozilla/5.0")
	headers.Set("Content-Type", "application/json")

	ctx := &FilterContext{
		Hostname:      "example.com",
		ClientIP:      "192.168.1.100",
		ServerAddr:    "example.com:443",
		Protocol:      "HTTPS",
		IsHTTPS:       true,
		CorrelationID: "test-123",
		Method:        "GET",
		URL:           testURL,
		Headers:       headers,
		UserAgent:     "Mozilla/5.0",
		ContentType:   "application/json",
		Timestamp:     time.Now(),
	}

	// Test packet-level fields (always available)
	if ctx.Hostname != "example.com" {
		t.Errorf("Expected hostname 'example.com', got '%s'", ctx.Hostname)
	}

	if ctx.ClientIP != "192.168.1.100" {
		t.Errorf("Expected client IP '192.168.1.100', got '%s'", ctx.ClientIP)
	}

	if !ctx.IsHTTPS {
		t.Error("Expected IsHTTPS to be true")
	}

	// Test HTTP-level fields (available during proxy inspection)
	if ctx.Method != "GET" {
		t.Errorf("Expected method 'GET', got '%s'", ctx.Method)
	}

	if ctx.URL.String() != "https://example.com/path?query=value" {
		t.Errorf("Expected URL 'https://example.com/path?query=value', got '%s'", ctx.URL.String())
	}

	if ctx.UserAgent != "Mozilla/5.0" {
		t.Errorf("Expected User-Agent 'Mozilla/5.0', got '%s'", ctx.UserAgent)
	}
}

// TestFilterMetrics tests the FilterMetrics struct
func TestFilterMetrics(t *testing.T) {
	metrics := &FilterMetrics{
		TotalRequests:    100,
		AllowedRequests:  80,
		BlockedRequests:  15,
		PassedRequests:   5,
		AvgExecutionTime: 5 * time.Millisecond,
		MaxExecutionTime: 25 * time.Millisecond,
		ErrorCount:       2,
	}

	if metrics.TotalRequests != 100 {
		t.Errorf("Expected total requests 100, got %d", metrics.TotalRequests)
	}

	expectedTotal := metrics.AllowedRequests + metrics.BlockedRequests + metrics.PassedRequests
	if expectedTotal != metrics.TotalRequests {
		t.Errorf("Request counts don't add up: %d + %d + %d = %d, expected %d",
			metrics.AllowedRequests, metrics.BlockedRequests, metrics.PassedRequests,
			expectedTotal, metrics.TotalRequests)
	}

	if metrics.AvgExecutionTime != 5*time.Millisecond {
		t.Errorf("Expected avg execution time 5ms, got %v", metrics.AvgExecutionTime)
	}
}

// TestDefaultAnalysisConfig tests the default configuration
func TestDefaultAnalysisConfig(t *testing.T) {
	config := DefaultAnalysisConfig()

	if config.Enabled {
		t.Error("Expected default config to be disabled")
	}

	if len(config.Plugins) != 0 {
		t.Errorf("Expected no default plugins, got %v", config.Plugins)
	}

	if config.Performance.TimeoutMs != 200 {
		t.Errorf("Expected default timeout 200ms, got %d", config.Performance.TimeoutMs)
	}

	if config.Performance.MaxBodySize != 1024 {
		t.Errorf("Expected default max body size 1024, got %d", config.Performance.MaxBodySize)
	}

	if !config.Performance.AsyncLogging {
		t.Error("Expected async logging to be enabled by default")
	}

	if !config.Performance.PacketFirst {
		t.Error("Expected packet-first to be enabled by default")
	}

	if config.Reporting.VerdictFile != "logs/verdicts.log" {
		t.Errorf("Expected default verdict file 'logs/verdicts.log', got '%s'", config.Reporting.VerdictFile)
	}

	if !config.BlockPage.Enabled {
		t.Error("Expected block page to be enabled by default")
	}

	if config.BlockPage.Template != "default" {
		t.Errorf("Expected default block page template 'default', got '%s'", config.BlockPage.Template)
	}
}

// MockFilter implements TrafficFilter for testing
type MockFilter struct {
	name     string
	priority int
	decision FilterDecision
}

func (m *MockFilter) GetName() string {
	return m.name
}

func (m *MockFilter) GetPriority() int {
	return m.priority
}

func (m *MockFilter) FilterPacket(ctx *FilterContext) FilterDecision {
	return m.decision
}

func (m *MockFilter) FilterRequestHeaders(ctx *FilterContext) FilterDecision {
	return m.decision
}

func (m *MockFilter) FilterResponseHeaders(ctx *FilterContext) FilterDecision {
	return m.decision
}

// TestMockFilter tests the mock filter implementation
func TestMockFilter(t *testing.T) {
	filter := &MockFilter{
		name:     "test-filter",
		priority: 50,
		decision: FilterDecision{
			Action: ActionBlock,
			Reason: "Test block",
		},
	}

	if filter.GetName() != "test-filter" {
		t.Errorf("Expected name 'test-filter', got '%s'", filter.GetName())
	}

	if filter.GetPriority() != 50 {
		t.Errorf("Expected priority 50, got %d", filter.GetPriority())
	}

	ctx := &FilterContext{Hostname: "test.com"}
	
	decision := filter.FilterPacket(ctx)
	if decision.Action != ActionBlock {
		t.Errorf("Expected action %s, got %s", ActionBlock, decision.Action)
	}

	decision = filter.FilterRequestHeaders(ctx)
	if decision.Reason != "Test block" {
		t.Errorf("Expected reason 'Test block', got '%s'", decision.Reason)
	}
}

// TestFilterDecisionEdgeCases tests edge cases for FilterDecision
func TestFilterDecisionEdgeCases(t *testing.T) {
	t.Run("EmptyDecision", func(t *testing.T) {
		decision := FilterDecision{}
		if decision.Action != "" {
			t.Errorf("Expected empty action, got %s", decision.Action)
		}
		if decision.Reason != "" {
			t.Errorf("Expected empty reason, got %s", decision.Reason)
		}
		if decision.Metadata != nil {
			t.Errorf("Expected nil metadata, got %v", decision.Metadata)
		}
	})

	t.Run("ComplexMetadata", func(t *testing.T) {
		metadata := map[string]interface{}{
			"rule_id":    123,
			"confidence": 0.95,
			"tags":       []string{"malware", "suspicious"},
			"nested": map[string]interface{}{
				"details": "complex data",
			},
		}
		
		decision := FilterDecision{
			Action:   ActionBlock,
			Reason:   "Complex rule match",
			Metadata: metadata,
		}

		if tags, ok := decision.Metadata["tags"].([]string); !ok || len(tags) != 2 {
			t.Errorf("Expected tags slice with 2 elements, got %v", decision.Metadata["tags"])
		}

		if nested, ok := decision.Metadata["nested"].(map[string]interface{}); !ok {
			t.Errorf("Expected nested map, got %v", decision.Metadata["nested"])
		} else if details, ok := nested["details"].(string); !ok || details != "complex data" {
			t.Errorf("Expected nested details 'complex data', got %v", details)
		}
	})
}

// TestFilterContextEdgeCases tests edge cases for FilterContext
func TestFilterContextEdgeCases(t *testing.T) {
	t.Run("EmptyContext", func(t *testing.T) {
		ctx := &FilterContext{}
		if ctx.Hostname != "" {
			t.Errorf("Expected empty hostname, got %s", ctx.Hostname)
		}
		if ctx.IsHTTPS {
			t.Error("Expected IsHTTPS to be false by default")
		}
		if ctx.Headers != nil {
			t.Errorf("Expected nil headers, got %v", ctx.Headers)
		}
	})

	t.Run("IPv6ClientIP", func(t *testing.T) {
		ctx := &FilterContext{
			ClientIP:   "2001:db8::1",
			ServerAddr: "[2001:db8::2]:443",
		}
		if ctx.ClientIP != "2001:db8::1" {
			t.Errorf("Expected IPv6 client IP, got %s", ctx.ClientIP)
		}
	})

	t.Run("MalformedURL", func(t *testing.T) {
		// Test that context can handle nil URL
		ctx := &FilterContext{
			URL: nil,
		}
		if ctx.URL != nil {
			t.Errorf("Expected nil URL, got %v", ctx.URL)
		}
	})

	t.Run("LargeHeaders", func(t *testing.T) {
		headers := make(http.Header)
		// Add many headers to test large header handling
		for i := 0; i < 100; i++ {
			headers.Set(fmt.Sprintf("X-Custom-Header-%d", i), fmt.Sprintf("value-%d", i))
		}

		ctx := &FilterContext{
			Headers: headers,
		}

		if len(ctx.Headers) != 100 {
			t.Errorf("Expected 100 headers, got %d", len(ctx.Headers))
		}
	})
}

// TestFilterMetricsCalculations tests metrics calculations
func TestFilterMetricsCalculations(t *testing.T) {
	t.Run("ZeroMetrics", func(t *testing.T) {
		metrics := &FilterMetrics{}
		if metrics.TotalRequests != 0 {
			t.Errorf("Expected 0 total requests, got %d", metrics.TotalRequests)
		}
		if metrics.AvgExecutionTime != 0 {
			t.Errorf("Expected 0 avg execution time, got %v", metrics.AvgExecutionTime)
		}
	})

	t.Run("HighVolumeMetrics", func(t *testing.T) {
		metrics := &FilterMetrics{
			TotalRequests:    1000000,
			AllowedRequests:  950000,
			BlockedRequests:  45000,
			PassedRequests:   5000,
			AvgExecutionTime: 1 * time.Microsecond,
			MaxExecutionTime: 50 * time.Millisecond,
		}

		total := metrics.AllowedRequests + metrics.BlockedRequests + metrics.PassedRequests
		if total != metrics.TotalRequests {
			t.Errorf("Request counts don't add up: got %d, expected %d", total, metrics.TotalRequests)
		}

		blockRate := float64(metrics.BlockedRequests) / float64(metrics.TotalRequests)
		expectedBlockRate := 0.045 // 4.5%
		if blockRate != expectedBlockRate {
			t.Errorf("Expected block rate %.3f, got %.3f", expectedBlockRate, blockRate)
		}
	})
}

// TestAnalysisConfigValidation tests configuration validation scenarios
func TestAnalysisConfigValidation(t *testing.T) {
	t.Run("InvalidTimeout", func(t *testing.T) {
		config := DefaultAnalysisConfig()
		config.Performance.TimeoutMs = -1
		
		// Note: We don't have validation logic yet, but this documents expected behavior
		// In a real implementation, we'd validate config values
		if config.Performance.TimeoutMs >= 0 {
			t.Errorf("Expected negative timeout to be invalid")
		}
	})

	t.Run("EmptyPlugins", func(t *testing.T) {
		config := DefaultAnalysisConfig()
		if len(config.Plugins) != 0 {
			t.Errorf("Expected empty plugins list, got %v", config.Plugins)
		}
	})

	t.Run("CustomConfiguration", func(t *testing.T) {
		config := &AnalysisConfig{
			Enabled: true,
			Plugins: []string{"customFilter", "anotherFilter"},
		}
		config.Performance.TimeoutMs = 500
		config.Performance.MaxBodySize = 2048
		
		if !config.Enabled {
			t.Error("Expected config to be enabled")
		}
		if len(config.Plugins) != 2 {
			t.Errorf("Expected 2 plugins, got %d", len(config.Plugins))
		}
		if config.Performance.TimeoutMs != 500 {
			t.Errorf("Expected timeout 500ms, got %d", config.Performance.TimeoutMs)
		}
	})
}

// TestFilterActionConstants tests that all constants are properly defined
func TestFilterActionConstants(t *testing.T) {
	actions := []FilterAction{ActionAllow, ActionBlock, ActionRedirect, ActionPass}
	expected := []string{"allow", "block", "redirect", "pass"}

	if len(actions) != len(expected) {
		t.Errorf("Expected %d actions, got %d", len(expected), len(actions))
	}

	for i, action := range actions {
		if action.String() != expected[i] {
			t.Errorf("Expected action %s, got %s", expected[i], action.String())
		}
	}
}

// BenchmarkFilterContext benchmarks FilterContext creation and usage
func BenchmarkFilterContext(b *testing.B) {
	testURL, _ := url.Parse("https://example.com/path")
	headers := make(http.Header)
	headers.Set("User-Agent", "Test-Agent")
	headers.Set("Content-Type", "application/json")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctx := &FilterContext{
			Hostname:      "example.com",
			ClientIP:      "192.168.1.100",
			ServerAddr:    "example.com:443",
			Protocol:      "HTTPS",
			IsHTTPS:       true,
			CorrelationID: "bench-test",
			Method:        "GET",
			URL:           testURL,
			Headers:       headers,
			UserAgent:     "Test-Agent",
			ContentType:   "application/json",
			Timestamp:     time.Now(),
		}
		
		// Simulate some basic context usage
		_ = ctx.Hostname
		_ = ctx.IsHTTPS
		_ = ctx.Headers.Get("User-Agent")
	}
}

// BenchmarkFilterDecision benchmarks FilterDecision creation
func BenchmarkFilterDecision(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		decision := FilterDecision{
			Action:   ActionBlock,
			Reason:   "Benchmark test",
			Metadata: map[string]interface{}{"test": true},
		}
		
		_ = decision.Action.String()
	}
}

// TestConcurrentAccess tests concurrent access to FilterContext and FilterDecision
func TestConcurrentAccess(t *testing.T) {
	ctx := &FilterContext{
		Hostname:  "example.com",
		ClientIP:  "192.168.1.100",
		IsHTTPS:   true,
		Headers:   make(http.Header),
		Timestamp: time.Now(),
	}
	ctx.Headers.Set("User-Agent", "Test-Agent")

	decision := FilterDecision{
		Action:   ActionAllow,
		Reason:   "Test reason",
		Metadata: make(map[string]interface{}),
	}
	decision.Metadata["test"] = true

	// Test concurrent reads - should be safe for immutable data
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func() {
			// Read operations
			_ = ctx.Hostname
			_ = ctx.IsHTTPS
			_ = ctx.Headers.Get("User-Agent")
			_ = decision.Action.String()
			_ = decision.Reason
			done <- true
		}()
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		select {
		case <-done:
			// Success
		case <-time.After(1 * time.Second):
			t.Error("Concurrent access test timed out")
		}
	}
}

// TestFilterResultLifecycle tests FilterResult struct
func TestFilterResultLifecycle(t *testing.T) {
	decision := FilterDecision{
		Action: ActionBlock,
		Reason: "Test block",
	}

	result := FilterResult{
		Decision:      decision,
		FilterName:    "test-filter",
		ExecutionTime: 5 * time.Millisecond,
		Error:         nil,
	}

	if result.Decision.Action != ActionBlock {
		t.Errorf("Expected action %s, got %s", ActionBlock, result.Decision.Action)
	}

	if result.FilterName != "test-filter" {
		t.Errorf("Expected filter name 'test-filter', got '%s'", result.FilterName)
	}

	if result.ExecutionTime != 5*time.Millisecond {
		t.Errorf("Expected execution time 5ms, got %v", result.ExecutionTime)
	}

	if result.Error != nil {
		t.Errorf("Expected no error, got %v", result.Error)
	}
}

// TestFilterResultWithError tests FilterResult with error conditions
func TestFilterResultWithError(t *testing.T) {
	testError := fmt.Errorf("filter execution failed")
	
	result := FilterResult{
		Decision: FilterDecision{
			Action: ActionPass,
			Reason: "Filter failed, passing to next",
		},
		FilterName:    "failing-filter",
		ExecutionTime: 100 * time.Millisecond,
		Error:         testError,
	}

	if result.Error == nil {
		t.Error("Expected error to be set")
	}

	if result.Error.Error() != "filter execution failed" {
		t.Errorf("Expected error message 'filter execution failed', got '%s'", result.Error.Error())
	}

	if result.Decision.Action != ActionPass {
		t.Errorf("Expected action %s for failed filter, got %s", ActionPass, result.Decision.Action)
	}
}