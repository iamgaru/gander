package filter

import (
	"context"
	"net"
)

// FilterResult represents the decision made by a filter
type FilterResult int

const (
	FilterAllow FilterResult = iota
	FilterBlock
	FilterInspect
	FilterBypass
	FilterCapture
)

// String returns the string representation of FilterResult
func (fr FilterResult) String() string {
	switch fr {
	case FilterAllow:
		return "allow"
	case FilterBlock:
		return "block"
	case FilterInspect:
		return "inspect"
	case FilterBypass:
		return "bypass"
	case FilterCapture:
		return "capture"
	default:
		return "unknown"
	}
}

// FilterContext contains information about the connection/request
type FilterContext struct {
	// Connection information
	ClientIP   net.IP
	ServerAddr string
	Domain     string
	Protocol   string

	// Request/response data
	RequestData  []byte
	ResponseData []byte

	// Additional metadata
	Metadata map[string]interface{}

	// Connection state
	IsHTTPS   bool
	IsRequest bool
}

// PacketFilter handles basic packet-level filtering (without inspection)
type PacketFilter interface {
	Name() string
	Priority() int
	ShouldFilter(ctx context.Context, filterCtx *FilterContext) (FilterResult, error)
}

// InspectionFilter handles deep packet inspection
type InspectionFilter interface {
	PacketFilter
	InspectRequest(ctx context.Context, filterCtx *FilterContext) (FilterResult, error)
	InspectResponse(ctx context.Context, filterCtx *FilterContext) (FilterResult, error)
}

// FilterProvider defines the interface for filter providers
type FilterProvider interface {
	Name() string
	Initialize(config map[string]interface{}) error
	GetPacketFilters() []PacketFilter
	GetInspectionFilters() []InspectionFilter
	Shutdown() error
}

// FilterHook allows for custom processing at various stages
type FilterHook interface {
	Name() string
	OnBeforeFilter(ctx context.Context, filterCtx *FilterContext) error
	OnAfterFilter(ctx context.Context, filterCtx *FilterContext, result FilterResult) error
}

// FilterRegistry manages the registration and discovery of filter providers
type FilterRegistry interface {
	RegisterProvider(name string, provider FilterProvider) error
	UnregisterProvider(name string) error
	GetProvider(name string) (FilterProvider, bool)
	GetProviders() map[string]FilterProvider
}

// FilterDecision represents the final decision after all filters have been applied
type FilterDecision struct {
	Result     FilterResult
	Reason     string
	Provider   string
	FilterName string
	ShouldLog  bool
	Metadata   map[string]interface{}
}

// ConnectionProfile contains connection characteristics for filtering decisions
type ConnectionProfile struct {
	ClientIP     net.IP
	ServerIP     net.IP
	ServerPort   int
	Domain       string
	Protocol     string
	TLSVersion   string
	UserAgent    string
	Timestamp    int64
	BytesRead    int64
	BytesWritten int64
}

// FilterChain represents a sequence of filters to be applied
type FilterChain interface {
	AddFilter(filter PacketFilter)
	AddInspectionFilter(filter InspectionFilter)
	ProcessPacket(ctx context.Context, filterCtx *FilterContext) (*FilterDecision, error)
	ProcessRequest(ctx context.Context, filterCtx *FilterContext) (*FilterDecision, error)
	ProcessResponse(ctx context.Context, filterCtx *FilterContext) (*FilterDecision, error)
}
