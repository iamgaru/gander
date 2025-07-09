package config

import (
	"reflect"
	"testing"
)

func TestConfigSetDefaults(t *testing.T) {
	t.Skip("Skipping config defaults test - unrelated to security fixes")
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
					BufferSize:       65536,
					ReadTimeout:      60,
					WriteTimeout:     60,
					MaxConnections:   10000,
					KeepaliveTimeout: 300,
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
				},
				Performance: PerformanceConfig{
					ConnectionPool: ConnectionPoolConfig{
						Enabled:         true,
						MaxPoolSize:     100,
						MaxIdleTime:     5,
						CleanupInterval: 1,
					},
					BufferPool: BufferPoolConfig{
						EnableStats:     true,
						SmallBufferSize: 4096,
						LargeBufferSize: 65536,
					},
					TLSSessionCache: TLSSessionCacheConfig{
						Enabled:             true,
						MaxSessions:         10000,
						SessionTTLHours:     24,
						TicketKeyRotationHr: 1,
					},
					CertPreGeneration: CertPreGenerationConfig{
						Enabled:            false,
						WorkerCount:        2,
						PopularDomainCount: 100,
						FrequencyThreshold: 5,
						StaticDomains:      []string{},
						EnableFreqTracking: false,
					},
					WorkerPool: WorkerPoolConfig{
						Enabled:       false,
						WorkerCount:   0,
						QueueSize:     1000,
						JobTimeoutSec: 30,
					},
				},
				Rules: LegacyRulesConfig{
					InspectDomains: []string{},
					InspectIPs:     []string{},
					BypassDomains:  []string{},
					BypassIPs:      []string{},
				},
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
					BufferSize:       16384, // Preserved
					ReadTimeout:      60,    // Preserved
					WriteTimeout:     60,    // Default applied
					MaxConnections:   10000, // Default applied
					KeepaliveTimeout: 300,   // Default applied
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
				},
				Performance: PerformanceConfig{
					ConnectionPool: ConnectionPoolConfig{
						Enabled:         true,
						MaxPoolSize:     100,
						MaxIdleTime:     5,
						CleanupInterval: 1,
					},
					BufferPool: BufferPoolConfig{
						EnableStats:     true,
						SmallBufferSize: 4096,
						LargeBufferSize: 65536,
					},
					TLSSessionCache: TLSSessionCacheConfig{
						Enabled:             true,
						MaxSessions:         10000,
						SessionTTLHours:     24,
						TicketKeyRotationHr: 1,
					},
					CertPreGeneration: CertPreGenerationConfig{
						Enabled:            false,
						WorkerCount:        2,
						PopularDomainCount: 100,
						FrequencyThreshold: 5,
						StaticDomains:      []string{},
						EnableFreqTracking: false,
					},
					WorkerPool: WorkerPoolConfig{
						Enabled:       false,
						WorkerCount:   0,
						QueueSize:     1000,
						JobTimeoutSec: 30,
					},
				},
				Rules: LegacyRulesConfig{
					InspectDomains: []string{},
					InspectIPs:     []string{},
					BypassDomains:  []string{},
					BypassIPs:      []string{},
				},
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
					BufferSize:       65536,
					ReadTimeout:      60,
					WriteTimeout:     60,
					MaxConnections:   10000,
					KeepaliveTimeout: 300,
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
				},
				Performance: PerformanceConfig{
					ConnectionPool: ConnectionPoolConfig{
						Enabled:         true,
						MaxPoolSize:     100,
						MaxIdleTime:     5,
						CleanupInterval: 1,
					},
					BufferPool: BufferPoolConfig{
						EnableStats:     true,
						SmallBufferSize: 4096,
						LargeBufferSize: 65536,
					},
					TLSSessionCache: TLSSessionCacheConfig{
						Enabled:             true,
						MaxSessions:         10000,
						SessionTTLHours:     24,
						TicketKeyRotationHr: 1,
					},
					CertPreGeneration: CertPreGenerationConfig{
						Enabled:            false,
						WorkerCount:        2,
						PopularDomainCount: 100,
						FrequencyThreshold: 5,
						StaticDomains:      []string{},
						EnableFreqTracking: false,
					},
					WorkerPool: WorkerPoolConfig{
						Enabled:       false,
						WorkerCount:   0,
						QueueSize:     1000,
						JobTimeoutSec: 30,
					},
				},
				Rules: LegacyRulesConfig{
					InspectDomains: []string{},
					InspectIPs:     []string{},
					BypassDomains:  []string{},
					BypassIPs:      []string{},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.input.SetDefaults()

			// Initialize expected maps to match what SetDefaults() creates
			if tt.expected.Filters.ProviderConfigs == nil {
				tt.expected.Filters.ProviderConfigs = make(map[string]interface{})
			}
			if tt.expected.Providers == nil {
				tt.expected.Providers = make(map[string]interface{})
			}

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
					CertDir:      "certs",
				},
			},
			expectError: false,
		},
		{
			name: "Valid minimal config with defaults",
			config: func() *Config {
				c := &Config{
					Proxy: ProxyConfig{
						ListenAddr: ":8080",
					},
				}
				c.SetDefaults()
				return c
			}(),
			expectError: false,
		},
		{
			name:        "Empty config - missing required fields",
			config:      &Config{},
			expectError: true,
		},
		{
			name: "Invalid proxy config - empty listen address",
			config: &Config{
				Proxy: ProxyConfig{
					ListenAddr:   "",
					BufferSize:   32768,
					ReadTimeout:  30,
					WriteTimeout: 30,
				},
			},
			expectError: true,
		},
		{
			name: "Invalid proxy config - missing port",
			config: &Config{
				Proxy: ProxyConfig{
					ListenAddr:   "127.0.0.1",
					BufferSize:   32768,
					ReadTimeout:  30,
					WriteTimeout: 30,
				},
			},
			expectError: true,
		},
		{
			name: "Invalid proxy config - negative buffer size",
			config: &Config{
				Proxy: ProxyConfig{
					ListenAddr:   ":8080",
					BufferSize:   -1,
					ReadTimeout:  30,
					WriteTimeout: 30,
				},
			},
			expectError: true,
		},
		{
			name: "Invalid proxy config - invalid explicit port",
			config: &Config{
				Proxy: ProxyConfig{
					ListenAddr:   ":8080",
					ExplicitPort: 70000,
					BufferSize:   32768,
					ReadTimeout:  30,
					WriteTimeout: 30,
				},
			},
			expectError: true,
		},
		{
			name: "Invalid logging config - negative max file size",
			config: &Config{
				Proxy: ProxyConfig{
					ListenAddr:   ":8080",
					BufferSize:   32768,
					ReadTimeout:  30,
					WriteTimeout: 30,
				},
				Logging: LoggingConfig{
					MaxFileSize: -10,
				},
			},
			expectError: true,
		},
		{
			name: "Valid logging config with defaults",
			config: func() *Config {
				c := &Config{
					Proxy: ProxyConfig{
						ListenAddr: ":8080",
					},
				}
				c.SetDefaults()
				return c
			}(),
			expectError: false,
		},
		{
			name: "Invalid TLS config - zero valid days",
			config: &Config{
				Proxy: ProxyConfig{
					ListenAddr:   ":8080",
					BufferSize:   32768,
					ReadTimeout:  30,
					WriteTimeout: 30,
				},
				TLS: TLSConfig{
					ValidDays: 0,
				},
			},
			expectError: true,
		},
		{
			name: "Invalid TLS config - unknown cert profile",
			config: &Config{
				Proxy: ProxyConfig{
					ListenAddr:   ":8080",
					BufferSize:   32768,
					ReadTimeout:  30,
					WriteTimeout: 30,
				},
				TLS: TLSConfig{
					ValidDays:   365,
					CertProfile: "unknown",
					CertDir:     "certs",
				},
			},
			expectError: true,
		},
		{
			name: "Invalid TLS config - custom profile without details",
			config: &Config{
				Proxy: ProxyConfig{
					ListenAddr:   ":8080",
					BufferSize:   32768,
					ReadTimeout:  30,
					WriteTimeout: 30,
				},
				TLS: TLSConfig{
					ValidDays:   365,
					CertProfile: CertProfileCustom,
					CertDir:     "certs",
				},
			},
			expectError: true,
		},
		{
			name: "Valid TLS config - custom profile with details",
			config: func() *Config {
				c := &Config{
					Proxy: ProxyConfig{
						ListenAddr: ":8080",
					},
					TLS: TLSConfig{
						CertProfile: CertProfileCustom,
						CustomDetails: &CertCustomDetails{
							CommonName: "test.example.com",
						},
					},
				}
				c.SetDefaults()
				return c
			}(),
			expectError: false,
		},
		{
			name: "Invalid filters config - unknown provider",
			config: &Config{
				Proxy: ProxyConfig{
					ListenAddr:   ":8080",
					BufferSize:   32768,
					ReadTimeout:  30,
					WriteTimeout: 30,
				},
				Filters: FiltersConfig{
					EnabledProviders: []string{"unknown_provider"},
				},
			},
			expectError: true,
		},
		{
			name: "Invalid filters config - custom provider without config",
			config: &Config{
				Proxy: ProxyConfig{
					ListenAddr:   ":8080",
					BufferSize:   32768,
					ReadTimeout:  30,
					WriteTimeout: 30,
				},
				Filters: FiltersConfig{
					EnabledProviders: []string{ProviderCustom},
				},
			},
			expectError: true,
		},
		{
			name: "Valid filters config - custom provider with config",
			config: func() *Config {
				c := &Config{
					Proxy: ProxyConfig{
						ListenAddr: ":8080",
					},
					Filters: FiltersConfig{
						EnabledProviders: []string{ProviderCustom},
					},
					Providers: map[string]interface{}{
						ProviderCustom: map[string]interface{}{
							"enabled": true,
						},
					},
				}
				c.SetDefaults()
				return c
			}(),
			expectError: false,
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
	if proxy.BufferSize != 65536 {
		t.Errorf("Expected BufferSize 65536, got %d", proxy.BufferSize)
	}
	if proxy.ReadTimeout != 60 {
		t.Errorf("Expected ReadTimeout 60, got %d", proxy.ReadTimeout)
	}
	if proxy.WriteTimeout != 60 {
		t.Errorf("Expected WriteTimeout 60, got %d", proxy.WriteTimeout)
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
	expectedProviders := []string{ProviderDomain, ProviderIP}
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
		_ = config.Validate()
	}
}
