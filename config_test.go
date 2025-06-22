package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Test config validation and edge cases
func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name      string
		config    Config
		shouldErr bool
	}{
		{
			name: "Valid minimal config",
			config: Config{
				Proxy: struct {
					ListenAddr   string `json:"listen_addr"`
					Transparent  bool   `json:"transparent"`
					ExplicitPort int    `json:"explicit_port"`
					BufferSize   int    `json:"buffer_size"`
					ReadTimeout  int    `json:"read_timeout_seconds"`
					WriteTimeout int    `json:"write_timeout_seconds"`
				}{
					ListenAddr: ":8080",
				},
				Logging: struct {
					LogFile     string `json:"log_file"`
					CaptureDir  string `json:"capture_dir"`
					MaxFileSize int64  `json:"max_file_size_mb"`
					EnableDebug bool   `json:"enable_debug"`
				}{
					LogFile:    "test.log",
					CaptureDir: "captures",
				},
			},
			shouldErr: false,
		},
		{
			name: "Config with custom buffer size",
			config: Config{
				Proxy: struct {
					ListenAddr   string `json:"listen_addr"`
					Transparent  bool   `json:"transparent"`
					ExplicitPort int    `json:"explicit_port"`
					BufferSize   int    `json:"buffer_size"`
					ReadTimeout  int    `json:"read_timeout_seconds"`
					WriteTimeout int    `json:"write_timeout_seconds"`
				}{
					ListenAddr: ":8080",
					BufferSize: 65536,
				},
				Logging: struct {
					LogFile     string `json:"log_file"`
					CaptureDir  string `json:"capture_dir"`
					MaxFileSize int64  `json:"max_file_size_mb"`
					EnableDebug bool   `json:"enable_debug"`
				}{
					LogFile:    "test.log",
					CaptureDir: "captures",
				},
			},
			shouldErr: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tempDir := t.TempDir()
			configFile := filepath.Join(tempDir, "test_config.json")

			data, err := json.MarshalIndent(test.config, "", "  ")
			if err != nil {
				t.Fatalf("Failed to marshal config: %v", err)
			}

			err = os.WriteFile(configFile, data, 0644)
			if err != nil {
				t.Fatalf("Failed to write config: %v", err)
			}

			config, err := loadConfig(configFile)
			if test.shouldErr && err == nil {
				t.Error("Expected error but got none")
			} else if !test.shouldErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			if !test.shouldErr && config != nil {
				// Test that defaults are applied when values are 0
				if test.config.Proxy.BufferSize == 0 && config.Proxy.BufferSize != 32768 {
					t.Errorf("Expected default buffer size 32768, got %d", config.Proxy.BufferSize)
				}
				if test.config.Proxy.BufferSize != 0 && config.Proxy.BufferSize != test.config.Proxy.BufferSize {
					t.Errorf("Expected buffer size %d, got %d", test.config.Proxy.BufferSize, config.Proxy.BufferSize)
				}
			}
		})
	}
}

// Test configuration with various rule combinations
func TestConfigRules(t *testing.T) {
	tempDir := t.TempDir()

	config := Config{
		Proxy: struct {
			ListenAddr   string `json:"listen_addr"`
			Transparent  bool   `json:"transparent"`
			ExplicitPort int    `json:"explicit_port"`
			BufferSize   int    `json:"buffer_size"`
			ReadTimeout  int    `json:"read_timeout_seconds"`
			WriteTimeout int    `json:"write_timeout_seconds"`
		}{
			ListenAddr: ":8080",
		},
		Logging: struct {
			LogFile     string `json:"log_file"`
			CaptureDir  string `json:"capture_dir"`
			MaxFileSize int64  `json:"max_file_size_mb"`
			EnableDebug bool   `json:"enable_debug"`
		}{
			LogFile:    filepath.Join(tempDir, "test.log"),
			CaptureDir: filepath.Join(tempDir, "captures"),
		},
		Rules: struct {
			InspectDomains []string `json:"inspect_domains"`
			InspectIPs     []string `json:"inspect_source_ips"`
			BypassDomains  []string `json:"bypass_domains"`
			BypassIPs      []string `json:"bypass_source_ips"`
		}{
			InspectDomains: []string{
				"example.com",
				"*.test.com",
				"api.service.com",
			},
			InspectIPs: []string{
				"192.168.1.100",
				"10.0.0.0/24",
				"172.16.0.1",
			},
			BypassDomains: []string{
				"update.microsoft.com",
				"*.google.com",
				"cdn.cloudflare.com",
			},
			BypassIPs: []string{
				"127.0.0.1",
				"169.254.0.0/16",
				"8.8.8.8",
			},
		},
	}

	configFile := filepath.Join(tempDir, "rules_config.json")
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal config: %v", err)
	}

	err = os.WriteFile(configFile, data, 0644)
	if err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}

	loadedConfig, err := loadConfig(configFile)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Verify rule arrays are loaded correctly
	if len(loadedConfig.Rules.InspectDomains) != 3 {
		t.Errorf("Expected 3 inspect domains, got %d", len(loadedConfig.Rules.InspectDomains))
	}

	if len(loadedConfig.Rules.InspectIPs) != 3 {
		t.Errorf("Expected 3 inspect IPs, got %d", len(loadedConfig.Rules.InspectIPs))
	}

	if len(loadedConfig.Rules.BypassDomains) != 3 {
		t.Errorf("Expected 3 bypass domains, got %d", len(loadedConfig.Rules.BypassDomains))
	}

	if len(loadedConfig.Rules.BypassIPs) != 3 {
		t.Errorf("Expected 3 bypass IPs, got %d", len(loadedConfig.Rules.BypassIPs))
	}
}

// Test TLS configuration
func TestTLSConfig(t *testing.T) {
	tempDir := t.TempDir()

	config := Config{
		Proxy: struct {
			ListenAddr   string `json:"listen_addr"`
			Transparent  bool   `json:"transparent"`
			ExplicitPort int    `json:"explicit_port"`
			BufferSize   int    `json:"buffer_size"`
			ReadTimeout  int    `json:"read_timeout_seconds"`
			WriteTimeout int    `json:"write_timeout_seconds"`
		}{
			ListenAddr: ":8080",
		},
		Logging: struct {
			LogFile     string `json:"log_file"`
			CaptureDir  string `json:"capture_dir"`
			MaxFileSize int64  `json:"max_file_size_mb"`
			EnableDebug bool   `json:"enable_debug"`
		}{
			LogFile:    filepath.Join(tempDir, "test.log"),
			CaptureDir: filepath.Join(tempDir, "captures"),
		},
		TLS: struct {
			CertFile          string `json:"cert_file"`
			KeyFile           string `json:"key_file"`
			CAFile            string `json:"ca_file"`
			CAKeyFile         string `json:"ca_key_file"`
			CertDir           string `json:"cert_dir"`
			AutoGenerate      bool   `json:"auto_generate"`
			ValidDays         int    `json:"valid_days"`
			UpstreamCertSniff bool   `json:"upstream_cert_sniff"`
		}{
			CertFile:     "proxy.crt",
			KeyFile:      "proxy.key",
			CAFile:       "ca.crt",
			CAKeyFile:    "ca.key",
			CertDir:      "", // Should get default
			AutoGenerate: true,
			ValidDays:    0, // Should get default
		},
	}

	configFile := filepath.Join(tempDir, "tls_config.json")
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal config: %v", err)
	}

	err = os.WriteFile(configFile, data, 0644)
	if err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}

	loadedConfig, err := loadConfig(configFile)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Check TLS defaults
	if loadedConfig.TLS.CertDir != "certs" {
		t.Errorf("Expected default cert dir 'certs', got '%s'", loadedConfig.TLS.CertDir)
	}

	if loadedConfig.TLS.ValidDays != 365 {
		t.Errorf("Expected default valid days 365, got %d", loadedConfig.TLS.ValidDays)
	}

	if !loadedConfig.TLS.AutoGenerate {
		t.Error("Expected AutoGenerate to be true")
	}
}

// Test empty and malformed configurations
func TestMalformedConfigs(t *testing.T) {
	tests := []struct {
		name      string
		content   string
		shouldErr bool
	}{
		{
			name:      "Empty JSON",
			content:   "{}",
			shouldErr: false, // Empty config should work with defaults
		},
		{
			name:      "Invalid JSON",
			content:   "{invalid json",
			shouldErr: true,
		},
		{
			name:      "JSON with trailing comma",
			content:   `{"proxy": {"listen_addr": ":8080",}}`,
			shouldErr: true,
		},
		{
			name: "Valid JSON with extra fields",
			content: `{
				"proxy": {
					"listen_addr": ":8080"
				},
				"logging": {
					"log_file": "test.log",
					"capture_dir": "captures"
				},
				"extra_field": "should_be_ignored"
			}`,
			shouldErr: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tempDir := t.TempDir()
			configFile := filepath.Join(tempDir, "test_config.json")

			err := os.WriteFile(configFile, []byte(test.content), 0644)
			if err != nil {
				t.Fatalf("Failed to write config: %v", err)
			}

			_, err = loadConfig(configFile)
			if test.shouldErr && err == nil {
				t.Error("Expected error but got none")
			} else if !test.shouldErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

// Benchmark config loading
func BenchmarkLoadConfig(b *testing.B) {
	tempDir := b.TempDir()
	configFile := filepath.Join(tempDir, "bench_config.json")

	config := Config{
		Proxy: struct {
			ListenAddr   string `json:"listen_addr"`
			Transparent  bool   `json:"transparent"`
			ExplicitPort int    `json:"explicit_port"`
			BufferSize   int    `json:"buffer_size"`
			ReadTimeout  int    `json:"read_timeout_seconds"`
			WriteTimeout int    `json:"write_timeout_seconds"`
		}{
			ListenAddr: ":8080",
		},
		Logging: struct {
			LogFile     string `json:"log_file"`
			CaptureDir  string `json:"capture_dir"`
			MaxFileSize int64  `json:"max_file_size_mb"`
			EnableDebug bool   `json:"enable_debug"`
		}{
			LogFile:    "test.log",
			CaptureDir: "captures",
		},
	}

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		b.Fatalf("Failed to marshal config: %v", err)
	}

	err = os.WriteFile(configFile, data, 0644)
	if err != nil {
		b.Fatalf("Failed to write config: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := loadConfig(configFile)
		if err != nil {
			b.Fatalf("Config loading failed: %v", err)
		}
	}
}
