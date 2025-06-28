package config

import (
	"fmt"
	"strings"
)

// Constants for TLS certificate profiles
const (
	CertProfileMinimal = "minimal"
	CertProfileCustom  = "custom"
)

// Constants for filter providers
const (
	ProviderDomain = "domain"
	ProviderIP     = "ip"
	ProviderCustom = "custom"
)

// ProxyConfig contains proxy server settings
type ProxyConfig struct {
	ListenAddr   string `json:"listen_addr"`
	Transparent  bool   `json:"transparent"`
	ExplicitPort int    `json:"explicit_port"`
	BufferSize   int    `json:"buffer_size"`
	ReadTimeout  int    `json:"read_timeout_seconds"`
	WriteTimeout int    `json:"write_timeout_seconds"`
}

// LoggingConfig contains logging settings
type LoggingConfig struct {
	LogFile     string `json:"log_file"`
	CaptureDir  string `json:"capture_dir"`
	MaxFileSize int64  `json:"max_file_size_mb"`
	EnableDebug bool   `json:"enable_debug"`
}

// TLSConfig contains TLS/certificate settings
type TLSConfig struct {
	CertFile          string             `json:"cert_file"`
	KeyFile           string             `json:"key_file"`
	CAFile            string             `json:"ca_file"`
	CAKeyFile         string             `json:"ca_key_file"`
	CertDir           string             `json:"cert_dir"`
	AutoGenerate      bool               `json:"auto_generate"`
	ValidDays         int                `json:"valid_days"`
	UpstreamCertSniff bool               `json:"upstream_cert_sniff"`
	CertProfile       string             `json:"cert_profile"` // "minimal" or "custom"
	CustomDetails     *CertCustomDetails `json:"custom_details,omitempty"`
}

// CertCustomDetails contains certificate customization details for stealth mode
type CertCustomDetails struct {
	Organization       []string `json:"organization,omitempty"`
	OrganizationalUnit []string `json:"organizational_unit,omitempty"`
	Country            []string `json:"country,omitempty"`
	Province           []string `json:"province,omitempty"`
	Locality           []string `json:"locality,omitempty"`
	StreetAddress      []string `json:"street_address,omitempty"`
	PostalCode         []string `json:"postal_code,omitempty"`
	CommonName         string   `json:"common_name,omitempty"`
}

// FiltersConfig contains filter system configuration
type FiltersConfig struct {
	EnabledProviders []string               `json:"enabled_providers"`
	ProviderConfigs  map[string]interface{} `json:"provider_configs"`
}

// LegacyRulesConfig maintains backward compatibility with existing configurations
type LegacyRulesConfig struct {
	InspectDomains []string `json:"inspect_domains"`
	InspectIPs     []string `json:"inspect_source_ips"`
	BypassDomains  []string `json:"bypass_domains"`
	BypassIPs      []string `json:"bypass_source_ips"`
}

// Config is the main configuration structure
type Config struct {
	Proxy     ProxyConfig            `json:"proxy"`
	Logging   LoggingConfig          `json:"logging"`
	TLS       TLSConfig              `json:"tls"`
	Filters   FiltersConfig          `json:"filters"`
	Providers map[string]interface{} `json:"providers"`

	// Legacy support - will be mapped to built-in providers
	Rules LegacyRulesConfig `json:"rules"`
}

// SetDefaults applies default values to the configuration
func (c *Config) SetDefaults() {
	// Proxy defaults
	if c.Proxy.BufferSize == 0 {
		c.Proxy.BufferSize = 32768
	}
	if c.Proxy.ReadTimeout == 0 {
		c.Proxy.ReadTimeout = 30
	}
	if c.Proxy.WriteTimeout == 0 {
		c.Proxy.WriteTimeout = 30
	}

	// Logging defaults
	if c.Logging.MaxFileSize == 0 {
		c.Logging.MaxFileSize = 100
	}

	// TLS defaults
	if c.TLS.ValidDays == 0 {
		c.TLS.ValidDays = 365
	}
	if c.TLS.CertDir == "" {
		c.TLS.CertDir = "certs"
	}

	// Filter defaults - enable built-in providers if none specified
	if len(c.Filters.EnabledProviders) == 0 {
		c.Filters.EnabledProviders = []string{ProviderDomain, ProviderIP}
	}
	if c.Filters.ProviderConfigs == nil {
		c.Filters.ProviderConfigs = make(map[string]interface{})
	}
	if c.Providers == nil {
		c.Providers = make(map[string]interface{})
	}
}

// Validate validates the configuration
func (c *Config) Validate() error {
	// Validate proxy configuration
	if err := c.validateProxy(); err != nil {
		return fmt.Errorf("proxy config validation failed: %w", err)
	}

	// Validate logging configuration
	if err := c.validateLogging(); err != nil {
		return fmt.Errorf("logging config validation failed: %w", err)
	}

	// Validate TLS configuration
	if err := c.validateTLS(); err != nil {
		return fmt.Errorf("TLS config validation failed: %w", err)
	}

	// Validate filters configuration
	if err := c.validateFilters(); err != nil {
		return fmt.Errorf("filters config validation failed: %w", err)
	}

	return nil
}

// validateProxy validates proxy configuration
func (c *Config) validateProxy() error {
	// ListenAddr is required
	if c.Proxy.ListenAddr == "" {
		return fmt.Errorf("proxy listen_addr is required")
	}

	// Validate listen address format
	if err := validateNetworkAddress(c.Proxy.ListenAddr); err != nil {
		return fmt.Errorf("invalid listen_addr: %w", err)
	}

	// Validate explicit port if set
	if c.Proxy.ExplicitPort != 0 {
		if c.Proxy.ExplicitPort < 1 || c.Proxy.ExplicitPort > 65535 {
			return fmt.Errorf("explicit_port must be between 1 and 65535, got %d", c.Proxy.ExplicitPort)
		}
	}

	// Validate buffer size
	if c.Proxy.BufferSize <= 0 {
		return fmt.Errorf("buffer_size must be positive, got %d", c.Proxy.BufferSize)
	}

	// Validate timeouts
	if c.Proxy.ReadTimeout <= 0 {
		return fmt.Errorf("read_timeout_seconds must be positive, got %d", c.Proxy.ReadTimeout)
	}
	if c.Proxy.WriteTimeout <= 0 {
		return fmt.Errorf("write_timeout_seconds must be positive, got %d", c.Proxy.WriteTimeout)
	}

	return nil
}

// validateLogging validates logging configuration
func (c *Config) validateLogging() error {
	// MaxFileSize must be positive
	if c.Logging.MaxFileSize <= 0 {
		return fmt.Errorf("max_file_size_mb must be positive, got %d", c.Logging.MaxFileSize)
	}

	// Validate log file path if specified
	if c.Logging.LogFile != "" {
		if err := validateFilePath(c.Logging.LogFile); err != nil {
			return fmt.Errorf("invalid log_file path: %w", err)
		}
	}

	// Validate capture directory if specified
	if c.Logging.CaptureDir != "" {
		if err := validateDirectoryPath(c.Logging.CaptureDir); err != nil {
			return fmt.Errorf("invalid capture_dir path: %w", err)
		}
	}

	return nil
}

// validateTLS validates TLS configuration
func (c *Config) validateTLS() error {
	// ValidDays must be positive
	if c.TLS.ValidDays <= 0 {
		return fmt.Errorf("valid_days must be positive, got %d", c.TLS.ValidDays)
	}

	// Validate cert profile
	if c.TLS.CertProfile != "" && c.TLS.CertProfile != CertProfileMinimal && c.TLS.CertProfile != CertProfileCustom {
		return fmt.Errorf("cert_profile must be '%s' or '%s', got '%s'", CertProfileMinimal, CertProfileCustom, c.TLS.CertProfile)
	}

	// If cert profile is custom, custom details should be provided
	if c.TLS.CertProfile == CertProfileCustom && c.TLS.CustomDetails == nil {
		return fmt.Errorf("custom_details required when cert_profile is '%s'", CertProfileCustom)
	}

	// Validate certificate file paths if specified
	if c.TLS.CertFile != "" {
		if err := validateFilePath(c.TLS.CertFile); err != nil {
			return fmt.Errorf("invalid cert_file path: %w", err)
		}
	}
	if c.TLS.KeyFile != "" {
		if err := validateFilePath(c.TLS.KeyFile); err != nil {
			return fmt.Errorf("invalid key_file path: %w", err)
		}
	}
	if c.TLS.CAFile != "" {
		if err := validateFilePath(c.TLS.CAFile); err != nil {
			return fmt.Errorf("invalid ca_file path: %w", err)
		}
	}
	if c.TLS.CAKeyFile != "" {
		if err := validateFilePath(c.TLS.CAKeyFile); err != nil {
			return fmt.Errorf("invalid ca_key_file path: %w", err)
		}
	}

	// Validate cert directory
	if c.TLS.CertDir != "" {
		if err := validateDirectoryPath(c.TLS.CertDir); err != nil {
			return fmt.Errorf("invalid cert_dir path: %w", err)
		}
	}

	return nil
}

// validateFilters validates filters configuration
func (c *Config) validateFilters() error {
	// Validate enabled providers
	validProviders := map[string]bool{
		ProviderDomain: true,
		ProviderIP:     true,
		ProviderCustom: true,
	}

	for _, provider := range c.Filters.EnabledProviders {
		if !validProviders[provider] {
			return fmt.Errorf("unknown filter provider: %s", provider)
		}
	}

	// Validate that provider configs exist for enabled providers
	for _, provider := range c.Filters.EnabledProviders {
		if provider == ProviderCustom {
			// Custom providers should have config in the main Providers section
			if c.Providers == nil || c.Providers[provider] == nil {
				return fmt.Errorf("custom provider '%s' enabled but no configuration found in providers section", provider)
			}
		}
	}

	return nil
}

// Helper validation functions

// validateNetworkAddress validates network address format (host:port)
func validateNetworkAddress(addr string) error {
	if addr == "" {
		return fmt.Errorf("address cannot be empty")
	}

	// Simple validation - should contain a colon for port
	if !strings.Contains(addr, ":") {
		return fmt.Errorf("address must include port (e.g., ':8080' or '127.0.0.1:8080')")
	}

	return nil
}

// validateFilePath validates file path format
func validateFilePath(path string) error {
	if path == "" {
		return fmt.Errorf("path cannot be empty")
	}

	// Check for invalid characters (basic validation)
	if strings.Contains(path, "\x00") {
		return fmt.Errorf("path contains null character")
	}

	return nil
}

// validateDirectoryPath validates directory path format
func validateDirectoryPath(path string) error {
	if path == "" {
		return fmt.Errorf("path cannot be empty")
	}

	// Check for invalid characters (basic validation)
	if strings.Contains(path, "\x00") {
		return fmt.Errorf("path contains null character")
	}

	return nil
}
