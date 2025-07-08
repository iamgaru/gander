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
	ListenAddr        string `json:"listen_addr"`
	Transparent       bool   `json:"transparent"`
	ExplicitPort      int    `json:"explicit_port"`
	BufferSize        int    `json:"buffer_size"`
	ReadTimeout       int    `json:"read_timeout_seconds"`
	WriteTimeout      int    `json:"write_timeout_seconds"`
	MaxConnections    int    `json:"max_connections"`
	WorkerPoolSize    int    `json:"worker_pool_size"`
	EnableKeepalive   bool   `json:"enable_keepalive"`
	KeepaliveTimeout  int    `json:"keepalive_timeout_seconds"`
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

// PerformanceConfig contains performance optimization settings
type PerformanceConfig struct {
	ConnectionPool    ConnectionPoolConfig    `json:"connection_pool"`
	BufferPool        BufferPoolConfig        `json:"buffer_pool"`
	TLSSessionCache   TLSSessionCacheConfig   `json:"tls_session_cache"`
	CertPreGeneration CertPreGenerationConfig `json:"cert_pregeneration"`
	WorkerPool        WorkerPoolConfig        `json:"worker_pool"`
}

// ConnectionPoolConfig contains connection pool settings
type ConnectionPoolConfig struct {
	Enabled         bool `json:"enabled"`
	MaxPoolSize     int  `json:"max_pool_size"`
	MaxIdleTime     int  `json:"max_idle_time_minutes"`
	CleanupInterval int  `json:"cleanup_interval_minutes"`
}

// BufferPoolConfig contains buffer pool settings
type BufferPoolConfig struct {
	EnableStats     bool `json:"enable_stats"`
	SmallBufferSize int  `json:"small_buffer_size"`
	LargeBufferSize int  `json:"large_buffer_size"`
}

// TLSSessionCacheConfig contains TLS session cache settings
type TLSSessionCacheConfig struct {
	Enabled             bool `json:"enabled"`
	MaxSessions         int  `json:"max_sessions"`
	SessionTTLHours     int  `json:"session_ttl_hours"`
	TicketKeyRotationHr int  `json:"ticket_key_rotation_hours"`
}

// CertPreGenerationConfig contains certificate pre-generation settings
type CertPreGenerationConfig struct {
	Enabled            bool     `json:"enabled"`
	WorkerCount        int      `json:"worker_count"`
	PopularDomainCount int      `json:"popular_domain_count"`
	FrequencyThreshold int      `json:"frequency_threshold"`
	StaticDomains      []string `json:"static_domains"`
	EnableFreqTracking bool     `json:"enable_frequency_tracking"`
}

// WorkerPoolConfig contains worker pool settings
type WorkerPoolConfig struct {
	Enabled       bool `json:"enabled"`
	WorkerCount   int  `json:"worker_count"`
	QueueSize     int  `json:"queue_size"`
	JobTimeoutSec int  `json:"job_timeout_seconds"`
}

// Config is the main configuration structure
type Config struct {
	Proxy       ProxyConfig            `json:"proxy"`
	Logging     LoggingConfig          `json:"logging"`
	TLS         TLSConfig              `json:"tls"`
	Filters     FiltersConfig          `json:"filters"`
	Providers   map[string]interface{} `json:"providers"`
	Performance PerformanceConfig      `json:"performance"`

	// Legacy support - will be mapped to built-in providers
	Rules LegacyRulesConfig `json:"rules"`
}

// SetDefaults applies default values to the configuration
func (c *Config) SetDefaults() {
	// Proxy defaults
	if c.Proxy.BufferSize == 0 {
		c.Proxy.BufferSize = 65536 // Increased from 32KB to 64KB
	}
	if c.Proxy.ReadTimeout == 0 {
		c.Proxy.ReadTimeout = 60 // Increased from 30s to 60s
	}
	if c.Proxy.WriteTimeout == 0 {
		c.Proxy.WriteTimeout = 60 // Increased from 30s to 60s
	}
	if c.Proxy.MaxConnections == 0 {
		c.Proxy.MaxConnections = 10000
	}
	if c.Proxy.WorkerPoolSize == 0 {
		c.Proxy.WorkerPoolSize = 0 // 0 means auto-detect (runtime.NumCPU() * 2)
	}
	if c.Proxy.KeepaliveTimeout == 0 {
		c.Proxy.KeepaliveTimeout = 300 // 5 minutes
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

	// Performance defaults
	c.setPerformanceDefaults()
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

// setPerformanceDefaults sets default values for performance optimizations
func (c *Config) setPerformanceDefaults() {
	// Connection pool defaults
	if !c.Performance.ConnectionPool.Enabled {
		c.Performance.ConnectionPool.Enabled = true // Enable by default
	}
	if c.Performance.ConnectionPool.MaxPoolSize == 0 {
		c.Performance.ConnectionPool.MaxPoolSize = 100
	}
	if c.Performance.ConnectionPool.MaxIdleTime == 0 {
		c.Performance.ConnectionPool.MaxIdleTime = 5 // 5 minutes
	}
	if c.Performance.ConnectionPool.CleanupInterval == 0 {
		c.Performance.ConnectionPool.CleanupInterval = 1 // 1 minute
	}

	// Buffer pool defaults
	c.Performance.BufferPool.EnableStats = true
	if c.Performance.BufferPool.SmallBufferSize == 0 {
		c.Performance.BufferPool.SmallBufferSize = 4096 // 4KB
	}
	if c.Performance.BufferPool.LargeBufferSize == 0 {
		c.Performance.BufferPool.LargeBufferSize = 65536 // 64KB
	}

	// TLS session cache defaults
	if !c.Performance.TLSSessionCache.Enabled {
		c.Performance.TLSSessionCache.Enabled = true // Enable by default
	}
	if c.Performance.TLSSessionCache.MaxSessions == 0 {
		c.Performance.TLSSessionCache.MaxSessions = 10000
	}
	if c.Performance.TLSSessionCache.SessionTTLHours == 0 {
		c.Performance.TLSSessionCache.SessionTTLHours = 24 // 24 hours
	}
	if c.Performance.TLSSessionCache.TicketKeyRotationHr == 0 {
		c.Performance.TLSSessionCache.TicketKeyRotationHr = 1 // 1 hour
	}

	// Certificate pre-generation defaults
	// Disabled by default - only enable if explicitly configured
	if c.Performance.CertPreGeneration.WorkerCount == 0 {
		c.Performance.CertPreGeneration.WorkerCount = 2
	}
	if c.Performance.CertPreGeneration.PopularDomainCount == 0 {
		c.Performance.CertPreGeneration.PopularDomainCount = 100
	}
	if c.Performance.CertPreGeneration.FrequencyThreshold == 0 {
		c.Performance.CertPreGeneration.FrequencyThreshold = 5
	}

	// Worker pool defaults
	// Note: Worker pool is disabled by default for better performance
	// Only enable if explicitly set to true in config
	if c.Performance.WorkerPool.WorkerCount == 0 {
		c.Performance.WorkerPool.WorkerCount = 0 // 0 means auto-detect
	}
	if c.Performance.WorkerPool.QueueSize == 0 {
		c.Performance.WorkerPool.QueueSize = 1000
	}
	if c.Performance.WorkerPool.JobTimeoutSec == 0 {
		c.Performance.WorkerPool.JobTimeoutSec = 30
	}
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
