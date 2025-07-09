package tls

import (
	"crypto/tls"
	"testing"
)

func TestSmartTLSConfig(t *testing.T) {
	// Test with debug mode disabled (production)
	smartTLS := NewSmartTLSConfig(false)
	
	// Test production domain - should be secure
	config := smartTLS.CreateTLSConfig("google.com", TLSContextRelay)
	if config.InsecureSkipVerify != false {
		t.Error("Production domain should use secure TLS verification")
	}
	if config.ServerName != "google.com" {
		t.Error("ServerName should be set correctly")
	}
	
	// Test development domain - should allow insecure
	config = smartTLS.CreateTLSConfig("localhost", TLSContextRelay)
	if config.InsecureSkipVerify != true {
		t.Error("Development domain should allow insecure TLS")
	}
	
	// Test certificate sniffing - should always allow insecure
	config = smartTLS.CreateTLSConfig("google.com", TLSContextSniffing)
	if config.InsecureSkipVerify != true {
		t.Error("Certificate sniffing should always allow insecure TLS")
	}
}

func TestSmartTLSConfigDebugMode(t *testing.T) {
	// Test with debug mode enabled
	smartTLS := NewSmartTLSConfig(true)
	
	// In debug mode, all domains should allow insecure TLS
	config := smartTLS.CreateTLSConfig("google.com", TLSContextRelay)
	if config.InsecureSkipVerify != true {
		t.Error("Debug mode should allow insecure TLS for all domains")
	}
	
	config = smartTLS.CreateTLSConfig("badssl.com", TLSContextPooling)
	if config.InsecureSkipVerify != true {
		t.Error("Debug mode should allow insecure TLS for all domains")
	}
}

func TestDevelopmentDomainDetection(t *testing.T) {
	smartTLS := NewSmartTLSConfig(false)
	
	testCases := []struct {
		domain       string
		shouldBeDev  bool
		description  string
	}{
		{"localhost", true, "localhost should be development"},
		{"localhost:3000", true, "localhost with port should be development"},
		{"127.0.0.1", true, "127.0.0.1 should be development"},
		{"127.0.0.1:8080", true, "127.0.0.1 with port should be development"},
		{"api.local", true, "*.local should be development"},
		{"test.dev", true, "*.dev should be development"},
		{"app.test", true, "*.test should be development"},
		{"service.internal", true, "*.internal should be development"},
		{"192.168.1.100", true, "192.168.* should be development"},
		{"10.0.0.1", true, "10.* should be development"},
		{"172.16.0.1", true, "172.16.* should be development"},
		{"google.com", false, "google.com should be production"},
		{"github.com", false, "github.com should be production"},
		{"badssl.com", false, "badssl.com should be production"},
	}
	
	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			isDev := smartTLS.isDevelopmentDomain(tc.domain)
			if isDev != tc.shouldBeDev {
				t.Errorf("Domain %s: expected isDevelopment=%v, got %v", 
					tc.domain, tc.shouldBeDev, isDev)
			}
		})
	}
}

func TestTLSConfigWithSessionCache(t *testing.T) {
	smartTLS := NewSmartTLSConfig(false)
	
	// Create a mock session cache
	cache := &mockSessionCache{}
	
	config := smartTLS.CreateTLSConfigWithSessionCache("google.com", TLSContextRelay, cache)
	
	if config.ClientSessionCache != cache {
		t.Error("Session cache should be set correctly")
	}
	
	if config.InsecureSkipVerify != false {
		t.Error("Production domain should use secure TLS even with session cache")
	}
}

func TestTLSContextValidation(t *testing.T) {
	testCases := []struct {
		context   TLSVerificationContext
		shouldErr bool
	}{
		{TLSContextRelay, false},
		{TLSContextSniffing, false},
		{TLSContextPooling, false},
		{TLSContextHealthCheck, false},
		{TLSVerificationContext("invalid"), true},
	}
	
	for _, tc := range testCases {
		err := ValidateTLSContext(tc.context)
		if tc.shouldErr && err == nil {
			t.Errorf("Expected error for context %s", tc.context)
		}
		if !tc.shouldErr && err != nil {
			t.Errorf("Unexpected error for context %s: %v", tc.context, err)
		}
	}
}

// Mock session cache for testing
type mockSessionCache struct{}

func (m *mockSessionCache) Get(sessionKey string) (*tls.ClientSessionState, bool) {
	return nil, false
}

func (m *mockSessionCache) Put(sessionKey string, cs *tls.ClientSessionState) {
	// no-op
}