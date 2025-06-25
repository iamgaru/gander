package config

import (
	"encoding/json"
	"fmt"
	"os"
)

// Loader handles configuration loading and processing
type Loader struct{}

// NewLoader creates a new configuration loader
func NewLoader() *Loader {
	return &Loader{}
}

// Load loads configuration from a file
func (l *Loader) Load(filename string) (*Config, error) {
	// Prevent using example config directly
	if filename == "config_example.json" {
		return nil, fmt.Errorf("cannot use config_example.json directly - copy it to config.json and customize it first")
	}

	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// Check if this looks like the example config (has warning fields)
	var rawConfig map[string]interface{}
	if err := json.Unmarshal(data, &rawConfig); err != nil {
		return nil, fmt.Errorf("failed to parse config JSON: %w", err)
	}

	if _, hasWarning := rawConfig["_WARNING"]; hasWarning {
		return nil, fmt.Errorf("this appears to be the example config file with warning fields - please create a clean config.json without the _WARNING, _NOTICE, and _SECURITY fields")
	}

	var config Config
	err = json.Unmarshal(data, &config)
	if err != nil {
		return nil, fmt.Errorf("failed to parse config JSON: %w", err)
	}

	// Apply defaults
	config.SetDefaults()

	// Handle legacy configuration migration
	if err := l.migrateLegacyConfig(&config); err != nil {
		return nil, fmt.Errorf("failed to migrate legacy config: %w", err)
	}

	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return &config, nil
}

// migrateLegacyConfig migrates legacy "rules" configuration to the new filter system
func (l *Loader) migrateLegacyConfig(config *Config) error {
	// If legacy rules are present, convert them to provider configs
	if len(config.Rules.InspectDomains) > 0 || len(config.Rules.InspectIPs) > 0 ||
		len(config.Rules.BypassDomains) > 0 || len(config.Rules.BypassIPs) > 0 {

		// Ensure domain provider is enabled
		if !l.containsString(config.Filters.EnabledProviders, "domain") {
			config.Filters.EnabledProviders = append(config.Filters.EnabledProviders, "domain")
		}

		// Ensure IP provider is enabled
		if !l.containsString(config.Filters.EnabledProviders, "ip") {
			config.Filters.EnabledProviders = append(config.Filters.EnabledProviders, "ip")
		}

		// Configure domain provider
		if _, exists := config.Filters.ProviderConfigs["domain"]; !exists {
			config.Filters.ProviderConfigs["domain"] = map[string]interface{}{
				"inspect_domains": config.Rules.InspectDomains,
				"bypass_domains":  config.Rules.BypassDomains,
			}
		}

		// Configure IP provider
		if _, exists := config.Filters.ProviderConfigs["ip"]; !exists {
			config.Filters.ProviderConfigs["ip"] = map[string]interface{}{
				"inspect_ips": config.Rules.InspectIPs,
				"bypass_ips":  config.Rules.BypassIPs,
			}
		}
	}

	return nil
}

// containsString checks if a string slice contains a specific string
func (l *Loader) containsString(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// LoadFromJSON loads configuration directly from JSON bytes
func (l *Loader) LoadFromJSON(data []byte) (*Config, error) {
	var config Config
	err := json.Unmarshal(data, &config)
	if err != nil {
		return nil, fmt.Errorf("failed to parse config JSON: %w", err)
	}

	config.SetDefaults()

	if err := l.migrateLegacyConfig(&config); err != nil {
		return nil, fmt.Errorf("failed to migrate legacy config: %w", err)
	}

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return &config, nil
}
