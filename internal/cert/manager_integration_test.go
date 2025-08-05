package cert

import (
	"testing"
	"time"
)

func TestCertManagerLogging(t *testing.T) {
	cm := NewCertificateManager(false)
	
	// Test logging callback integration
	type LogCall struct {
		Action   string
		Domain   string
		Duration time.Duration
		Status   string
		Extra    map[string]interface{}
	}
	
	var loggedCalls []LogCall
	
	// Set logging callback
	cm.SetCertLogger(func(action, domain string, duration time.Duration, status string, extra map[string]interface{}) {
		loggedCalls = append(loggedCalls, LogCall{
			Action:   action,
			Domain:   domain, 
			Duration: duration,
			Status:   status,
			Extra:    extra,
		})
	})
	
	// Test that cache operations trigger logging
	// We can't easily test GetCertificate without full initialization,
	// but we can test that the callback is set correctly
	if cm.logFunc == nil {
		t.Error("Certificate logging callback should be set")
	}
	
	// Test that calling the callback works
	cm.logFunc("test_action", "test.com", 50*time.Millisecond, "success", map[string]interface{}{"test": "value"})
	
	if len(loggedCalls) != 1 {
		t.Errorf("Expected 1 logged call, got %d", len(loggedCalls))
	}
	
	if len(loggedCalls) > 0 {
		call := loggedCalls[0]
		if call.Action != "test_action" {
			t.Errorf("Expected action 'test_action', got '%s'", call.Action)
		}
		if call.Domain != "test.com" {
			t.Errorf("Expected domain 'test.com', got '%s'", call.Domain)
		}
		if call.Duration != 50*time.Millisecond {
			t.Errorf("Expected duration 50ms, got %v", call.Duration)
		}
		if call.Status != "success" {
			t.Errorf("Expected status 'success', got '%s'", call.Status)
		}
		if call.Extra["test"] != "value" {
			t.Errorf("Expected extra field 'test'='value', got %v", call.Extra["test"])
		}
	}
}

func TestCertManagerWithoutLogging(t *testing.T) {
	cm := NewCertificateManager(false)
	
	// Should not panic when logFunc is nil
	if cm.logFunc != nil {
		t.Error("Certificate logging callback should initially be nil")
	}
	
	// Should be able to call SetCertLogger with nil without issues
	cm.SetCertLogger(nil)
	if cm.logFunc != nil {
		t.Error("Certificate logging callback should be nil after setting to nil")
	}
}