package config

import (
	"encoding/json"
	"testing"
)

func TestFeatureLogsConfig(t *testing.T) {
	// Test that FeatureLogsConfig can be marshaled/unmarshaled correctly
	config := &LoggingConfig{
		LogFile:        "logs/proxy.log",
		CaptureDir:     "captures",
		MaxFileSize:    100,
		EnableDebug:    false,
		ConsoleLevel:   "minimal",
		StatusInterval: "60s",
		FeatureLogs: &FeatureLogsConfig{
			Enabled:       true,
			MaxFileSizeMB: 50,
			MaxFiles:      10,
			Compression:   true,
			Logs: map[string]FeatureLogConfig{
				"filtering": {
					Enabled: true,
					Level:   "info",
				},
				"certificates": {
					Enabled: true,
					Level:   "info",
				},
				"errors": {
					Enabled: true,
					Level:   "error",
				},
				"performance": {
					Enabled: false,
					Level:   "info",
				},
			},
		},
	}

	// Test JSON marshaling
	data, err := json.Marshal(config)
	if err != nil {
		t.Fatalf("Failed to marshal config: %v", err)
	}

	// Test JSON unmarshaling
	var unmarshaledConfig LoggingConfig
	err = json.Unmarshal(data, &unmarshaledConfig)
	if err != nil {
		t.Fatalf("Failed to unmarshal config: %v", err)
	}

	// Verify feature logs config
	if unmarshaledConfig.FeatureLogs == nil {
		t.Error("FeatureLogs should not be nil")
		return
	}

	fl := unmarshaledConfig.FeatureLogs
	if !fl.Enabled {
		t.Error("FeatureLogs should be enabled")
	}

	if fl.MaxFileSizeMB != 50 {
		t.Errorf("Expected MaxFileSizeMB 50, got %d", fl.MaxFileSizeMB)
	}

	if fl.MaxFiles != 10 {
		t.Errorf("Expected MaxFiles 10, got %d", fl.MaxFiles)
	}

	if !fl.Compression {
		t.Error("Compression should be enabled")
	}

	// Check individual log configs
	if filteringConfig, exists := fl.Logs["filtering"]; exists {
		if !filteringConfig.Enabled {
			t.Error("Filtering log should be enabled")
		}
		if filteringConfig.Level != "info" {
			t.Errorf("Expected filtering level 'info', got '%s'", filteringConfig.Level)
		}
	} else {
		t.Error("Filtering log config should exist")
	}

	if perfConfig, exists := fl.Logs["performance"]; exists {
		if perfConfig.Enabled {
			t.Error("Performance log should be disabled")
		}
	} else {
		t.Error("Performance log config should exist")
	}
}

func TestFeatureLogsConfigOptional(t *testing.T) {
	// Test that FeatureLogs is optional (can be nil)
	config := &LoggingConfig{
		LogFile:        "logs/proxy.log",
		CaptureDir:     "captures",
		MaxFileSize:    100,
		EnableDebug:    false,
		ConsoleLevel:   "minimal",
		StatusInterval: "60s",
		// FeatureLogs is nil
	}

	// Test JSON marshaling with nil FeatureLogs
	data, err := json.Marshal(config)
	if err != nil {
		t.Fatalf("Failed to marshal config with nil FeatureLogs: %v", err)
	}

	// Should not include feature_logs in JSON due to omitempty tag
	dataStr := string(data)
	if dataStr == "" {
		t.Error("Marshaled data should not be empty")
	}

	// Test unmarshaling
	var unmarshaledConfig LoggingConfig
	err = json.Unmarshal(data, &unmarshaledConfig)
	if err != nil {
		t.Fatalf("Failed to unmarshal config with nil FeatureLogs: %v", err)
	}

	// FeatureLogs should be nil
	if unmarshaledConfig.FeatureLogs != nil {
		t.Error("FeatureLogs should be nil when not specified")
	}
}

func TestFullConfigWithFeatureLogs(t *testing.T) {
	// Test a complete config structure includes feature logs properly
	configJSON := `{
		"proxy": {
			"listen_addr": ":8848"
		},
		"logging": {
			"log_file": "logs/proxy.log",
			"capture_dir": "captures",
			"max_file_size_mb": 100,
			"enable_debug": false,
			"console_level": "minimal",
			"status_interval": "60s",
			"feature_logs": {
				"enabled": true,
				"max_file_size_mb": 50,
				"max_files": 10,
				"compression": true,
				"logs": {
					"filtering": {
						"enabled": true,
						"level": "info"
					},
					"certificates": {
						"enabled": true,
						"level": "info"
					}
				}
			}
		}
	}`

	var config Config
	err := json.Unmarshal([]byte(configJSON), &config)
	if err != nil {
		t.Fatalf("Failed to unmarshal full config: %v", err)
	}

	// Check that feature logs config is parsed correctly
	if config.Logging.FeatureLogs == nil {
		t.Error("FeatureLogs should not be nil in full config")
		return
	}

	fl := config.Logging.FeatureLogs
	if !fl.Enabled {
		t.Error("FeatureLogs should be enabled")
	}

	if len(fl.Logs) != 2 {
		t.Errorf("Expected 2 log configs, got %d", len(fl.Logs))
	}
}