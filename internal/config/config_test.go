package config

import (
	"reflect"
	"testing"
)

func TestConfigSetDefaults(t *testing.T) {
	tests := []struct {
		name     string
		input    *Config
		expected *Config
	}{
		{
			name:  "Empty config gets all defaults",
			input: &Config{},
			expected: &Config{
				Proxy: ProxyConfig{
					BufferSize:   32768,
					ReadTimeout:  30,
					WriteTimeout: 30,
				},
				Logging: LoggingConfig{
					MaxFileSize: 100,
				},
				TLS: TLSConfig{
					ValidDays: 365,
					CertDir:   "certs",
				},
				Filters: FiltersConfig{
					EnabledProviders: []string{"domain", "ip"},
					ProviderConfigs:  make(map[string]interface{}),
				},
				Providers: make(map[string]interface{}),
			},
		},
		{
			name: "Partial config preserves existing values",
			input: &Config{
				Proxy: ProxyConfig{
					BufferSize:  16384, // Custom value
					ReadTimeout: 60,    // Custom value
				},
				TLS: TLSConfig{
					ValidDays: 180, // Custom value
				},
			},
			expected: &Config{
				Proxy: ProxyConfig{
					BufferSize:   16384, // Preserved
					ReadTimeout:  60,    // Preserved
					WriteTimeout: 30,    // Default applied
				},
				Logging: LoggingConfig{
					MaxFileSize: 100, // Default applied
				},
				TLS: TLSConfig{
					ValidDays: 180,     // Preserved
					CertDir:   "certs", // Default applied
				},
				Filters: FiltersConfig{
					EnabledProviders: []string{"domain", "ip"},
					ProviderConfigs:  make(map[string]interface{}),
				},
				Providers: make(map[string]interface{}),
			},
		},
		{
			name: "Custom filters config preserved",
			input: &Config{
				Filters: FiltersConfig{
					EnabledProviders: []string{"custom", "another"},
				},
			},
			expected: &Config{
				Proxy: ProxyConfig{
					BufferSize:   32768,
					ReadTimeout:  30,
					WriteTimeout: 30,
				},
				Logging: LoggingConfig{
					MaxFileSize: 100,
				},
				TLS: TLSConfig{
					ValidDays: 365,
					CertDir:   "certs",
				},
				Filters: FiltersConfig{
					EnabledProviders: []string{"custom", "another"}, // Preserved
					ProviderConfigs:  make(map[string]interface{}),
				},
				Providers: make(map[string]interface{}),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.input.SetDefaults()
			if !reflect.DeepEqual(tt.input, tt.expected) {
				t.Errorf("SetDefaults() = %+v, want %+v", tt.input, tt.expected)
			}
		})
	}
}

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name        string
		config      *Config
		expectError bool
	}{
		{
			name: "Valid complete config",
			config: &Config{
				Proxy: ProxyConfig{
					ListenAddr:   ":8080",
					BufferSize:   32768,
					ReadTimeout:  30,
					WriteTimeout: 30,
				},
				Logging: LoggingConfig{
					LogFile:     "proxy.log",
					CaptureDir:  "captures",
					MaxFileSize: 100,
				},
				TLS: TLSConfig{
					CertFile:     "cert.pem",
					KeyFile:      "key.pem",
					CAFile:       "ca.pem",
					CAKeyFile:    "ca-key.pem",
					ValidDays:    365,
					AutoGenerate: true,
				},
			},
			expectError: false,
		},
		{
			name: "Minimal valid config",
			config: &Config{
				Proxy: ProxyConfig{
					ListenAddr: ":8080",
				},
			},
			expectError: false,
		},
		{
			name:        "Empty config",
			config:      &Config{},
			expectError: false, // Currently no validation rules
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.expectError && err == nil {
				t.Error("Validate() expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Validate() unexpected error: %v", err)
			}
		})
	}
}

func TestProxyConfigDefaults(t *testing.T) {
	config := &Config{}
	config.SetDefaults()

	proxy := config.Proxy
	if proxy.BufferSize != 32768 {
		t.Errorf("Expected BufferSize 32768, got %d", proxy.BufferSize)
	}
	if proxy.ReadTimeout != 30 {
		t.Errorf("Expected ReadTimeout 30, got %d", proxy.ReadTimeout)
	}
	if proxy.WriteTimeout != 30 {
		t.Errorf("Expected WriteTimeout 30, got %d", proxy.WriteTimeout)
	}
}

func TestLoggingConfigDefaults(t *testing.T) {
	config := &Config{}
	config.SetDefaults()

	logging := config.Logging
	if logging.MaxFileSize != 100 {
		t.Errorf("Expected MaxFileSize 100, got %d", logging.MaxFileSize)
	}
}

func TestTLSConfigDefaults(t *testing.T) {
	config := &Config{}
	config.SetDefaults()

	tls := config.TLS
	if tls.ValidDays != 365 {
		t.Errorf("Expected ValidDays 365, got %d", tls.ValidDays)
	}
	if tls.CertDir != "certs" {
		t.Errorf("Expected CertDir 'certs', got %s", tls.CertDir)
	}
}

func TestFiltersConfigDefaults(t *testing.T) {
	config := &Config{}
	config.SetDefaults()

	filters := config.Filters
	expectedProviders := []string{"domain", "ip"}
	if !reflect.DeepEqual(filters.EnabledProviders, expectedProviders) {
		t.Errorf("Expected EnabledProviders %v, got %v", expectedProviders, filters.EnabledProviders)
	}
	if filters.ProviderConfigs == nil {
		t.Error("Expected ProviderConfigs to be initialized")
	}
	if config.Providers == nil {
		t.Error("Expected Providers to be initialized")
	}
}

func TestCertCustomDetails(t *testing.T) {
	customDetails := &CertCustomDetails{
		Organization:       []string{"Test Org"},
		OrganizationalUnit: []string{"Test Unit"},
		Country:            []string{"US"},
		Province:           []string{"CA"},
		Locality:           []string{"San Francisco"},
		CommonName:         "test.example.com",
	}

	// Test that all fields are properly set
	if len(customDetails.Organization) != 1 || customDetails.Organization[0] != "Test Org" {
		t.Error("Organization not set correctly")
	}
	if customDetails.CommonName != "test.example.com" {
		t.Error("CommonName not set correctly")
	}
}

func TestLegacyRulesConfig(t *testing.T) {
	rules := LegacyRulesConfig{
		InspectDomains: []string{"example.com", "test.com"},
		InspectIPs:     []string{"192.168.1.100", "10.0.0.0/24"},
		BypassDomains:  []string{"bypass.com"},
		BypassIPs:      []string{"127.0.0.1"},
	}

	// Test that legacy rules are properly structured
	if len(rules.InspectDomains) != 2 {
		t.Errorf("Expected 2 inspect domains, got %d", len(rules.InspectDomains))
	}
	if len(rules.InspectIPs) != 2 {
		t.Errorf("Expected 2 inspect IPs, got %d", len(rules.InspectIPs))
	}
	if len(rules.BypassDomains) != 1 {
		t.Errorf("Expected 1 bypass domain, got %d", len(rules.BypassDomains))
	}
}

func TestTLSCertProfiles(t *testing.T) {
	tests := []struct {
		name    string
		profile string
		valid   bool
	}{
		{"Minimal profile", "minimal", true},
		{"Custom profile", "custom", true},
		{"Empty profile", "", true},          // Should be valid (use default)
		{"Unknown profile", "unknown", true}, // No validation yet
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &TLSConfig{
				CertProfile: tt.profile,
			}

			// Test that profile is set correctly
			if config.CertProfile != tt.profile {
				t.Errorf("Expected profile %s, got %s", tt.profile, config.CertProfile)
			}
		})
	}
}

func TestConfigStructureIntegrity(t *testing.T) {
	// Test that all config sections are properly nested
	config := &Config{
		Proxy: ProxyConfig{
			ListenAddr:   ":8080",
			Transparent:  true,
			ExplicitPort: 3128,
			BufferSize:   65536,
			ReadTimeout:  60,
			WriteTimeout: 60,
		},
		Logging: LoggingConfig{
			LogFile:     "test.log",
			CaptureDir:  "test-captures",
			MaxFileSize: 200,
			EnableDebug: true,
		},
		TLS: TLSConfig{
			CertFile:          "test.crt",
			KeyFile:           "test.key",
			CAFile:            "ca.crt",
			CAKeyFile:         "ca.key",
			CertDir:           "test-certs",
			AutoGenerate:      true,
			ValidDays:         730,
			UpstreamCertSniff: true,
			CertProfile:       "custom",
			CustomDetails: &CertCustomDetails{
				Organization: []string{"Test Corp"},
				CommonName:   "test.example.com",
			},
		},
		Filters: FiltersConfig{
			EnabledProviders: []string{"domain", "ip", "custom"},
			ProviderConfigs: map[string]interface{}{
				"domain": map[string]interface{}{
					"inspect_domains": []string{"example.com"},
				},
			},
		},
		Providers: map[string]interface{}{
			"custom": map[string]interface{}{
				"enabled": true,
			},
		},
		Rules: LegacyRulesConfig{
			InspectDomains: []string{"legacy.com"},
			InspectIPs:     []string{"192.168.1.0/24"},
		},
	}

	// Verify structure integrity
	if config.Proxy.ListenAddr != ":8080" {
		t.Error("Proxy config not properly nested")
	}
	if config.Logging.EnableDebug != true {
		t.Error("Logging config not properly nested")
	}
	if config.TLS.CustomDetails == nil {
		t.Error("TLS CustomDetails not properly nested")
	}
	if len(config.Filters.EnabledProviders) != 3 {
		t.Error("Filters config not properly nested")
	}
	if len(config.Rules.InspectDomains) != 1 {
		t.Error("Legacy rules not properly nested")
	}
}

// Benchmark tests for performance validation
func BenchmarkSetDefaults(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		config := &Config{}
		config.SetDefaults()
	}
}

func BenchmarkValidate(b *testing.B) {
	config := &Config{}
	config.SetDefaults()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		config.Validate()
	}
}
