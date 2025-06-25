package config

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
		c.Filters.EnabledProviders = []string{"domain", "ip"}
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
	// Add validation logic here
	return nil
}
