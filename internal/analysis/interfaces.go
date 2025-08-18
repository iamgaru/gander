package analysis

import (
	"net/http"
	"net/url"
	"time"
)

// TrafficFilter defines the interface for pluggable traffic analysis filters
type TrafficFilter interface {
	// GetName returns the unique identifier for this filter
	GetName() string
	
	// GetPriority returns the execution priority (lower number = higher priority)
	// Packet filters should use priority 1-99, proxy filters 100-199
	GetPriority() int
	
	// FilterPacket performs packet-level filtering on hostname/IP/URL
	// This is the first phase of filtering, designed for fast decisions
	FilterPacket(ctx *FilterContext) FilterDecision
	
	// FilterRequestHeaders performs header-based analysis on HTTP requests
	// Only called if packet filter returns ActionPass
	FilterRequestHeaders(ctx *FilterContext) FilterDecision
	
	// FilterResponseHeaders performs header-based analysis on HTTP responses
	// Only called if request filtering didn't block the connection
	FilterResponseHeaders(ctx *FilterContext) FilterDecision
	
	// Future expansion points for body analysis with strict size limits
	// FilterRequestBody(ctx *FilterContext, body []byte) FilterDecision
	// FilterResponseBody(ctx *FilterContext, body []byte) FilterDecision
}

// FilterDecision represents the result of a filter's analysis
type FilterDecision struct {
	Action   FilterAction               `json:"action"`   // The decision made by the filter
	Reason   string                     `json:"reason"`   // Human-readable explanation
	Target   string                     `json:"target"`   // For redirects (future use)
	Metadata map[string]interface{}     `json:"metadata"` // Plugin-specific data
	BlockPage string                    `json:"-"`        // Custom block page HTML (not logged)
}

// FilterAction defines the possible actions a filter can take
type FilterAction string

const (
	ActionAllow    FilterAction = "allow"    // Allow the connection/request
	ActionBlock    FilterAction = "block"    // Block the connection/request
	ActionRedirect FilterAction = "redirect" // Redirect to different URL (future)
	ActionPass     FilterAction = "pass"     // No decision, continue to next filter
)

// String returns the string representation of FilterAction
func (fa FilterAction) String() string {
	return string(fa)
}

// FilterContext provides the context data for filter analysis
type FilterContext struct {
	// Packet-level data (always available)
	Hostname     string      `json:"hostname"`      // Target hostname
	ClientIP     string      `json:"client_ip"`     // Source IP address
	ServerAddr   string      `json:"server_addr"`   // Target server address
	Protocol     string      `json:"protocol"`      // HTTP, HTTPS, WebSocket
	IsHTTPS      bool        `json:"is_https"`      // Whether connection uses TLS
	CorrelationID string     `json:"correlation_id"` // Request correlation ID
	
	// HTTP-level data (available during proxy inspection)
	Method       string      `json:"method"`        // HTTP method (GET, POST, etc.)
	URL          *url.URL    `json:"url"`           // Full request URL
	Headers      http.Header `json:"headers"`       // HTTP headers
	UserAgent    string      `json:"user_agent"`    // User-Agent header
	ContentType  string      `json:"content_type"`  // Content-Type header
	
	// Timing and metadata
	Timestamp    time.Time   `json:"timestamp"`     // When the request was made
	
	// Future: Request/response body data with size limits
	// RequestBody  []byte      `json:"-"`             // Request body (max 1024 bytes)
	// ResponseBody []byte      `json:"-"`             // Response body (max 1024 bytes)
}

// FilterMetrics tracks performance and usage statistics for each filter
type FilterMetrics struct {
	TotalRequests    int64         `json:"total_requests"`
	AllowedRequests  int64         `json:"allowed_requests"`
	BlockedRequests  int64         `json:"blocked_requests"`
	PassedRequests   int64         `json:"passed_requests"`
	AvgExecutionTime time.Duration `json:"avg_execution_time"`
	MaxExecutionTime time.Duration `json:"max_execution_time"`
	ErrorCount       int64         `json:"error_count"`
	LastError        error         `json:"-"`
	LastErrorTime    time.Time     `json:"last_error_time"`
}

// FilterResult combines a decision with execution metadata
type FilterResult struct {
	Decision      FilterDecision `json:"decision"`
	FilterName    string         `json:"filter_name"`
	ExecutionTime time.Duration  `json:"execution_time"`
	Error         error          `json:"error,omitempty"`
}

// AnalysisConfig defines configuration for the traffic analysis system
type AnalysisConfig struct {
	Enabled bool     `json:"enabled"`
	Plugins []string `json:"plugins"`
	
	Performance struct {
		TimeoutMs        int  `json:"timeout_ms"`        // Total timeout for all filters (200ms default)
		MaxBodySize      int  `json:"max_body_size"`     // Max body size for analysis (1024 bytes)
		AsyncLogging     bool `json:"async_logging"`     // Whether to log asynchronously
		PacketFirst      bool `json:"packet_first"`      // Execute packet filters before proxy filters
		MaxConcurrent    int  `json:"max_concurrent"`    // Max concurrent filter executions
	} `json:"performance"`
	
	Reporting struct {
		VerdictFile   string `json:"verdict_file"`   // Central verdict log file
		PluginLogs    bool   `json:"plugin_logs"`    // Enable per-plugin logs
		MetricsInterval string `json:"metrics_interval"` // How often to report metrics
	} `json:"reporting"`
	
	BlockPage struct {
		Enabled       bool   `json:"enabled"`        // Whether to serve block pages
		Template      string `json:"template"`       // Block page template name
		ShowReason    bool   `json:"show_reason"`    // Include block reason in page
		ShowTimestamp bool   `json:"show_timestamp"` // Include timestamp in page
		CustomCSS     string `json:"custom_css"`     // Custom CSS for block page
	} `json:"block_page"`
	
	// Plugin-specific configurations
	Filters map[string]interface{} `json:"filters"`
}

// DefaultAnalysisConfig returns a configuration with sensible defaults
func DefaultAnalysisConfig() *AnalysisConfig {
	return &AnalysisConfig{
		Enabled: false, // Disabled by default for safety
		Plugins: []string{}, // No plugins enabled by default
		Performance: struct {
			TimeoutMs        int  `json:"timeout_ms"`
			MaxBodySize      int  `json:"max_body_size"`
			AsyncLogging     bool `json:"async_logging"`
			PacketFirst      bool `json:"packet_first"`
			MaxConcurrent    int  `json:"max_concurrent"`
		}{
			TimeoutMs:     200,  // 200ms total timeout
			MaxBodySize:   1024, // 1KB body analysis limit
			AsyncLogging:  true, // Non-blocking logging
			PacketFirst:   true, // Packet filters execute first
			MaxConcurrent: 10,   // Max 10 concurrent filter executions
		},
		Reporting: struct {
			VerdictFile   string `json:"verdict_file"`
			PluginLogs    bool   `json:"plugin_logs"`
			MetricsInterval string `json:"metrics_interval"`
		}{
			VerdictFile:   "logs/verdicts.log",
			PluginLogs:    false, // Disabled by default
			MetricsInterval: "60s", // Report metrics every minute
		},
		BlockPage: struct {
			Enabled       bool   `json:"enabled"`
			Template      string `json:"template"`
			ShowReason    bool   `json:"show_reason"`
			ShowTimestamp bool   `json:"show_timestamp"`
			CustomCSS     string `json:"custom_css"`
		}{
			Enabled:       true, // Enable block pages by default
			Template:      "default",
			ShowReason:    true,
			ShowTimestamp: true,
			CustomCSS:     "", // No custom CSS by default
		},
		Filters: make(map[string]interface{}),
	}
}